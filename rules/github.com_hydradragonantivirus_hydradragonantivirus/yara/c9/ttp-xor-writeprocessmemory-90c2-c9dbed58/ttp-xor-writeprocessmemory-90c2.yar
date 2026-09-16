rule TTP_XOR_WriteProcessMemory_90c2 {
  strings:
    $key_90c2 = { c7 b0 [2] f5 92 [2] f3 a7 [2] dd a7 [2] e2 bb }

  condition:
    any of them
}