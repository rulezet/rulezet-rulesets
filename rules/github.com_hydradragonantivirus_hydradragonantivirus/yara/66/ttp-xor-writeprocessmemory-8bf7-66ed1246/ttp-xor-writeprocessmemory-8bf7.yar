rule TTP_XOR_WriteProcessMemory_8bf7 {
  strings:
    $key_8bf7 = { dc 85 [2] ee a7 [2] e8 92 [2] c6 92 [2] f9 8e }

  condition:
    any of them
}