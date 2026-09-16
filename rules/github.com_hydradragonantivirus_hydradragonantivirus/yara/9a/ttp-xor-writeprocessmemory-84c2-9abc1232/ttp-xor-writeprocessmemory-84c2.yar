rule TTP_XOR_WriteProcessMemory_84c2 {
  strings:
    $key_84c2 = { d3 b0 [2] e1 92 [2] e7 a7 [2] c9 a7 [2] f6 bb }

  condition:
    any of them
}