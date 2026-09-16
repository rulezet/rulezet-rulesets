rule TTP_XOR_WriteProcessMemory_85c4 {
  strings:
    $key_85c4 = { d2 b6 [2] e0 94 [2] e6 a1 [2] c8 a1 [2] f7 bd }

  condition:
    any of them
}