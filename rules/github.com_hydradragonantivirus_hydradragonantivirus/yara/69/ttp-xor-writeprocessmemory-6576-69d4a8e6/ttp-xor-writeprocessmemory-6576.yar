rule TTP_XOR_WriteProcessMemory_6576 {
  strings:
    $key_6576 = { 32 04 [2] 00 26 [2] 06 13 [2] 28 13 [2] 17 0f }

  condition:
    any of them
}