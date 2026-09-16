rule TTP_XOR_WriteProcessMemory_85d2 {
  strings:
    $key_85d2 = { d2 a0 [2] e0 82 [2] e6 b7 [2] c8 b7 [2] f7 ab }

  condition:
    any of them
}