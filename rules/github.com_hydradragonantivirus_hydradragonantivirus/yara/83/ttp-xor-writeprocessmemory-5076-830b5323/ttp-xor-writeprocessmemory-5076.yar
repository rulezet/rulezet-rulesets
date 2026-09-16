rule TTP_XOR_WriteProcessMemory_5076 {
  strings:
    $key_5076 = { 07 04 [2] 35 26 [2] 33 13 [2] 1d 13 [2] 22 0f }

  condition:
    any of them
}