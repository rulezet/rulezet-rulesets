rule TTP_XOR_WriteProcessMemory_af72 {
  strings:
    $key_af72 = { f8 00 [2] ca 22 [2] cc 17 [2] e2 17 [2] dd 0b }

  condition:
    any of them
}