rule TTP_XOR_WriteProcessMemory_17c2 {
  strings:
    $key_17c2 = { 40 b0 [2] 72 92 [2] 74 a7 [2] 5a a7 [2] 65 bb }

  condition:
    any of them
}