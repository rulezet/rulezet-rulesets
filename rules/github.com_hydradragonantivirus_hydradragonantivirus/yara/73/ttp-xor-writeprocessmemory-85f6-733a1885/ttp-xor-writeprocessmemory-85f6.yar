rule TTP_XOR_WriteProcessMemory_85f6 {
  strings:
    $key_85f6 = { d2 84 [2] e0 a6 [2] e6 93 [2] c8 93 [2] f7 8f }

  condition:
    any of them
}