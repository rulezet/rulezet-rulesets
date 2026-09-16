rule TTP_XOR_WriteProcessMemory_13c2 {
  strings:
    $key_13c2 = { 44 b0 [2] 76 92 [2] 70 a7 [2] 5e a7 [2] 61 bb }

  condition:
    any of them
}