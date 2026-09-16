rule TTP_XOR_WriteProcessMemory_8150 {
  strings:
    $key_8150 = { d6 22 [2] e4 00 [2] e2 35 [2] cc 35 [2] f3 29 }

  condition:
    any of them
}