rule TTP_XOR_WriteProcessMemory_8bf8 {
  strings:
    $key_8bf8 = { dc 8a [2] ee a8 [2] e8 9d [2] c6 9d [2] f9 81 }

  condition:
    any of them
}