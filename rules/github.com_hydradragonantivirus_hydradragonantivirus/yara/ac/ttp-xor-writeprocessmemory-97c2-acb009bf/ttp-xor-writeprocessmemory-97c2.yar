rule TTP_XOR_WriteProcessMemory_97c2 {
  strings:
    $key_97c2 = { c0 b0 [2] f2 92 [2] f4 a7 [2] da a7 [2] e5 bb }

  condition:
    any of them
}