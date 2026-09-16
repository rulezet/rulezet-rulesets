rule TTP_XOR_WriteProcessMemory_8dc5 {
  strings:
    $key_8dc5 = { da b7 [2] e8 95 [2] ee a0 [2] c0 a0 [2] ff bc }

  condition:
    any of them
}