rule TTP_XOR_WriteProcessMemory_af00 {
  strings:
    $key_af00 = { f8 72 [2] ca 50 [2] cc 65 [2] e2 65 [2] dd 79 }

  condition:
    any of them
}