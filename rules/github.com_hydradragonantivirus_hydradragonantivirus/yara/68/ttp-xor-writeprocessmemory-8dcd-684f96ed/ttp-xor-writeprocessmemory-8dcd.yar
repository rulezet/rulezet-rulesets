rule TTP_XOR_WriteProcessMemory_8dcd {
  strings:
    $key_8dcd = { da bf [2] e8 9d [2] ee a8 [2] c0 a8 [2] ff b4 }

  condition:
    any of them
}