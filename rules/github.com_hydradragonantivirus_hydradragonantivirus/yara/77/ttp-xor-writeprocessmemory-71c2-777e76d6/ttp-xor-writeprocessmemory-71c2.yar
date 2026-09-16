rule TTP_XOR_WriteProcessMemory_71c2 {
  strings:
    $key_71c2 = { 26 b0 [2] 14 92 [2] 12 a7 [2] 3c a7 [2] 03 bb }

  condition:
    any of them
}