rule TTP_XOR_WriteProcessMemory_53c2 {
  strings:
    $key_53c2 = { 04 b0 [2] 36 92 [2] 30 a7 [2] 1e a7 [2] 21 bb }

  condition:
    any of them
}