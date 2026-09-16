rule TTP_XOR_WriteProcessMemory_8bf6 {
  strings:
    $key_8bf6 = { dc 84 [2] ee a6 [2] e8 93 [2] c6 93 [2] f9 8f }

  condition:
    any of them
}