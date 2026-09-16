rule TTP_XOR_WriteProcessMemory_8bf2 {
  strings:
    $key_8bf2 = { dc 80 [2] ee a2 [2] e8 97 [2] c6 97 [2] f9 8b }

  condition:
    any of them
}