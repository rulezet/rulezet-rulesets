rule TTP_XOR_WriteProcessMemory_af7b {
  strings:
    $key_af7b = { f8 09 [2] ca 2b [2] cc 1e [2] e2 1e [2] dd 02 }

  condition:
    any of them
}