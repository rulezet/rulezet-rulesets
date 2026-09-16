rule TTP_XOR_WriteProcessMemory_c1c2 {
  strings:
    $key_c1c2 = { 96 b0 [2] a4 92 [2] a2 a7 [2] 8c a7 [2] b3 bb }

  condition:
    any of them
}