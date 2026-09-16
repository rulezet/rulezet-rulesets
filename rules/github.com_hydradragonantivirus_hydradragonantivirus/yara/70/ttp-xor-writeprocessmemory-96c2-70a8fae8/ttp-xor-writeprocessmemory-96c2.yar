rule TTP_XOR_WriteProcessMemory_96c2 {
  strings:
    $key_96c2 = { c1 b0 [2] f3 92 [2] f5 a7 [2] db a7 [2] e4 bb }

  condition:
    any of them
}