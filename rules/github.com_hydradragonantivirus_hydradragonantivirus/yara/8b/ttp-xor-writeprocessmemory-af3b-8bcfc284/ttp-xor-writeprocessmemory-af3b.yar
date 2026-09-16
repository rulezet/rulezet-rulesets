rule TTP_XOR_WriteProcessMemory_af3b {
  strings:
    $key_af3b = { f8 49 [2] ca 6b [2] cc 5e [2] e2 5e [2] dd 42 }

  condition:
    any of them
}