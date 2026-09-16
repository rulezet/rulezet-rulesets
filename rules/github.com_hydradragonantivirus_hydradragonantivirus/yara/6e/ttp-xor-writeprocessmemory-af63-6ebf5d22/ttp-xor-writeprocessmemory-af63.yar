rule TTP_XOR_WriteProcessMemory_af63 {
  strings:
    $key_af63 = { f8 11 [2] ca 33 [2] cc 06 [2] e2 06 [2] dd 1a }

  condition:
    any of them
}