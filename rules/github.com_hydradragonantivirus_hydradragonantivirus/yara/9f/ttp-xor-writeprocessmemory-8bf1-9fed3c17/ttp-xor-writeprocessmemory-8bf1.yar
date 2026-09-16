rule TTP_XOR_WriteProcessMemory_8bf1 {
  strings:
    $key_8bf1 = { dc 83 [2] ee a1 [2] e8 94 [2] c6 94 [2] f9 88 }

  condition:
    any of them
}