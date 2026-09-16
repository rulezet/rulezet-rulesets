rule TTP_XOR_WriteProcessMemory_e4c2 {
  strings:
    $key_e4c2 = { b3 b0 [2] 81 92 [2] 87 a7 [2] a9 a7 [2] 96 bb }

  condition:
    any of them
}