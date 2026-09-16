rule TTP_XOR_WriteProcessMemory_46c2 {
  strings:
    $key_46c2 = { 11 b0 [2] 23 92 [2] 25 a7 [2] 0b a7 [2] 34 bb }

  condition:
    any of them
}