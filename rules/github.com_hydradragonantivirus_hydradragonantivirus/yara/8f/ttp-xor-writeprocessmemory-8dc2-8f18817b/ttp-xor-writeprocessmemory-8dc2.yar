rule TTP_XOR_WriteProcessMemory_8dc2 {
  strings:
    $key_8dc2 = { da b0 [2] e8 92 [2] ee a7 [2] c0 a7 [2] ff bb }

  condition:
    any of them
}