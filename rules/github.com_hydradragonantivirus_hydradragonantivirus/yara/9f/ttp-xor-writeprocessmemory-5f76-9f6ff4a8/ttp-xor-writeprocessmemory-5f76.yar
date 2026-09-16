rule TTP_XOR_WriteProcessMemory_5f76 {
  strings:
    $key_5f76 = { 08 04 [2] 3a 26 [2] 3c 13 [2] 12 13 [2] 2d 0f }

  condition:
    any of them
}