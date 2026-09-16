rule TTP_XOR_WriteProcessMemory_8526 {
  strings:
    $key_8526 = { d2 54 [2] e0 76 [2] e6 43 [2] c8 43 [2] f7 5f }

  condition:
    any of them
}