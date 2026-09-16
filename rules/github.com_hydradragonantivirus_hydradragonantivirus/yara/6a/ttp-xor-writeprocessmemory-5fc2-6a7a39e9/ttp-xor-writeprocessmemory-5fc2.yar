rule TTP_XOR_WriteProcessMemory_5fc2 {
  strings:
    $key_5fc2 = { 08 b0 [2] 3a 92 [2] 3c a7 [2] 12 a7 [2] 2d bb }

  condition:
    any of them
}