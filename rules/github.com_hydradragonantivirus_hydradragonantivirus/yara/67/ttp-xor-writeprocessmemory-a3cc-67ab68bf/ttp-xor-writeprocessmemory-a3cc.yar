rule TTP_XOR_WriteProcessMemory_a3cc {
  strings:
    $key_a3cc = { f4 be [2] c6 9c [2] c0 a9 [2] ee a9 [2] d1 b5 }

  condition:
    any of them
}