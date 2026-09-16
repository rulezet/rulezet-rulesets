rule TTP_XOR_WriteProcessMemory_8450 {
  strings:
    $key_8450 = { d3 22 [2] e1 00 [2] e7 35 [2] c9 35 [2] f6 29 }

  condition:
    any of them
}