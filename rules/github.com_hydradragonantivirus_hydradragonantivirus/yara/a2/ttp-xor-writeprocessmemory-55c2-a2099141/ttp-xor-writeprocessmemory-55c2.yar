rule TTP_XOR_WriteProcessMemory_55c2 {
  strings:
    $key_55c2 = { 02 b0 [2] 30 92 [2] 36 a7 [2] 18 a7 [2] 27 bb }

  condition:
    any of them
}