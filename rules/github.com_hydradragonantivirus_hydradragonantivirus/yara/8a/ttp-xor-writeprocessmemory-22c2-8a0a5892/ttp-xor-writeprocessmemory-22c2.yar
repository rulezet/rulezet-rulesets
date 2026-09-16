rule TTP_XOR_WriteProcessMemory_22c2 {
  strings:
    $key_22c2 = { 75 b0 [2] 47 92 [2] 41 a7 [2] 6f a7 [2] 50 bb }

  condition:
    any of them
}