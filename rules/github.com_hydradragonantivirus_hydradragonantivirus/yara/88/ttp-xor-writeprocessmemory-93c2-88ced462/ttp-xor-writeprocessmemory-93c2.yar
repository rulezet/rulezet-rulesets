rule TTP_XOR_WriteProcessMemory_93c2 {
  strings:
    $key_93c2 = { c4 b0 [2] f6 92 [2] f0 a7 [2] de a7 [2] e1 bb }

  condition:
    any of them
}