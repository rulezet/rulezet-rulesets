rule TTP_XOR_WriteProcessMemory_0b76 {
  strings:
    $key_0b76 = { 5c 04 [2] 6e 26 [2] 68 13 [2] 46 13 [2] 79 0f }

  condition:
    any of them
}