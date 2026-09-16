rule TTP_XOR_WriteProcessMemory_2546 {
  strings:
    $key_2546 = { 72 34 [2] 40 16 [2] 46 23 [2] 68 23 [2] 57 3f }

  condition:
    any of them
}