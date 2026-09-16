rule TTP_XOR_WriteProcessMemory_85b1 {
  strings:
    $key_85b1 = { d2 c3 [2] e0 e1 [2] e6 d4 [2] c8 d4 [2] f7 c8 }

  condition:
    any of them
}