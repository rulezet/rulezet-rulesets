rule TTP_XOR_WriteProcessMemory_91c2 {
  strings:
    $key_91c2 = { c6 b0 [2] f4 92 [2] f2 a7 [2] dc a7 [2] e3 bb }

  condition:
    any of them
}