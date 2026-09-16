rule TTP_XOR_WriteProcessMemory_20c2 {
  strings:
    $key_20c2 = { 77 b0 [2] 45 92 [2] 43 a7 [2] 6d a7 [2] 52 bb }

  condition:
    any of them
}