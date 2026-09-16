rule TTP_XOR_WriteProcessMemory_2576 {
  strings:
    $key_2576 = { 72 04 [2] 40 26 [2] 46 13 [2] 68 13 [2] 57 0f }

  condition:
    any of them
}