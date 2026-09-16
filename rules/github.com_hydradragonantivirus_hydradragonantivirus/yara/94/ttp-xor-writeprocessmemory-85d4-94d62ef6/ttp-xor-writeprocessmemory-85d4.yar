rule TTP_XOR_WriteProcessMemory_85d4 {
  strings:
    $key_85d4 = { d2 a6 [2] e0 84 [2] e6 b1 [2] c8 b1 [2] f7 ad }

  condition:
    any of them
}