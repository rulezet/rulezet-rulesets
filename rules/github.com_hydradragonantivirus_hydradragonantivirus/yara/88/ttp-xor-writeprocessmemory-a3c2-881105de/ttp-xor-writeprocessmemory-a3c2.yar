rule TTP_XOR_WriteProcessMemory_a3c2 {
  strings:
    $key_a3c2 = { f4 b0 [2] c6 92 [2] c0 a7 [2] ee a7 [2] d1 bb }

  condition:
    any of them
}