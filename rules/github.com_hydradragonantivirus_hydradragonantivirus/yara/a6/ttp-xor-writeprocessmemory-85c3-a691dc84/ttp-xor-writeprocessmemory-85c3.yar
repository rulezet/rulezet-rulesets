rule TTP_XOR_WriteProcessMemory_85c3 {
  strings:
    $key_85c3 = { d2 b1 [2] e0 93 [2] e6 a6 [2] c8 a6 [2] f7 ba }

  condition:
    any of them
}