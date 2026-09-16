rule TTP_XOR_WriteProcessMemory_77c2 {
  strings:
    $key_77c2 = { 20 b0 [2] 12 92 [2] 14 a7 [2] 3a a7 [2] 05 bb }

  condition:
    any of them
}