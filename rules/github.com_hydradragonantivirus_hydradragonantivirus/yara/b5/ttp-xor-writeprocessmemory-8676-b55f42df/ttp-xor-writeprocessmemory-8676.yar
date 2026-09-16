rule TTP_XOR_WriteProcessMemory_8676 {
  strings:
    $key_8676 = { d1 04 [2] e3 26 [2] e5 13 [2] cb 13 [2] f4 0f }

  condition:
    any of them
}