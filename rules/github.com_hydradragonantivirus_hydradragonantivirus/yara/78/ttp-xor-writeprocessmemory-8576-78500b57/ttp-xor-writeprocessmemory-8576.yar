rule TTP_XOR_WriteProcessMemory_8576 {
  strings:
    $key_8576 = { d2 04 [2] e0 26 [2] e6 13 [2] c8 13 [2] f7 0f }

  condition:
    any of them
}