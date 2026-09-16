rule TTP_XOR_WriteProcessMemory_03c2 {
  strings:
    $key_03c2 = { 54 b0 [2] 66 92 [2] 60 a7 [2] 4e a7 [2] 71 bb }

  condition:
    any of them
}