rule TTP_XOR_WriteProcessMemory_c4c2 {
  strings:
    $key_c4c2 = { 93 b0 [2] a1 92 [2] a7 a7 [2] 89 a7 [2] b6 bb }

  condition:
    any of them
}