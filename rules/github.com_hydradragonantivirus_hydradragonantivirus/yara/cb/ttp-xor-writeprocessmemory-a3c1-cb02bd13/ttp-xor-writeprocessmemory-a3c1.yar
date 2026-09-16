rule TTP_XOR_WriteProcessMemory_a3c1 {
  strings:
    $key_a3c1 = { f4 b3 [2] c6 91 [2] c0 a4 [2] ee a4 [2] d1 b8 }

  condition:
    any of them
}