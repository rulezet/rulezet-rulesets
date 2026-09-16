rule TTP_XOR_WriteProcessMemory_af2b {
  strings:
    $key_af2b = { f8 59 [2] ca 7b [2] cc 4e [2] e2 4e [2] dd 52 }

  condition:
    any of them
}