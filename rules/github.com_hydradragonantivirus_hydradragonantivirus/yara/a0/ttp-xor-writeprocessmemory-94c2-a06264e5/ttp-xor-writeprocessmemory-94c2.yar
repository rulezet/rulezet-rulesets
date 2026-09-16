rule TTP_XOR_WriteProcessMemory_94c2 {
  strings:
    $key_94c2 = { c3 b0 [2] f1 92 [2] f7 a7 [2] d9 a7 [2] e6 bb }

  condition:
    any of them
}