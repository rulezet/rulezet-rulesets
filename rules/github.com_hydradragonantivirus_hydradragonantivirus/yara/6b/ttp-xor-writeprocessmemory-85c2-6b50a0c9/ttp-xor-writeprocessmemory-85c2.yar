rule TTP_XOR_WriteProcessMemory_85c2 {
  strings:
    $key_85c2 = { d2 b0 [2] e0 92 [2] e6 a7 [2] c8 a7 [2] f7 bb }

  condition:
    any of them
}