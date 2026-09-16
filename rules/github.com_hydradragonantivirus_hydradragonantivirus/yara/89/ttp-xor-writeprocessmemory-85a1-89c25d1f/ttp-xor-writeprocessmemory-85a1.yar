rule TTP_XOR_WriteProcessMemory_85a1 {
  strings:
    $key_85a1 = { d2 d3 [2] e0 f1 [2] e6 c4 [2] c8 c4 [2] f7 d8 }

  condition:
    any of them
}