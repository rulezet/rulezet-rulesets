rule TTP_XOR_WriteProcessMemory_af6b {
  strings:
    $key_af6b = { f8 19 [2] ca 3b [2] cc 0e [2] e2 0e [2] dd 12 }

  condition:
    any of them
}