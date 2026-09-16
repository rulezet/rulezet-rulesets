rule TTP_XOR_WriteProcessMemory_95c2 {
  strings:
    $key_95c2 = { c2 b0 [2] f0 92 [2] f6 a7 [2] d8 a7 [2] e7 bb }

  condition:
    any of them
}