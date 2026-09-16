rule TTP_XOR_WriteProcessMemory_25c2 {
  strings:
    $key_25c2 = { 72 b0 [2] 40 92 [2] 46 a7 [2] 68 a7 [2] 57 bb }

  condition:
    any of them
}