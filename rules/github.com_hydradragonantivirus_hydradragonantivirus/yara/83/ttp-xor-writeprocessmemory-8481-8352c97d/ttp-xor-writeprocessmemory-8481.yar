rule TTP_XOR_WriteProcessMemory_8481 {
  strings:
    $key_8481 = { d3 f3 [2] e1 d1 [2] e7 e4 [2] c9 e4 [2] f6 f8 }

  condition:
    any of them
}