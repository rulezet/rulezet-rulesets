rule TTP_XOR_WriteProcessMemory_a3c7 {
  strings:
    $key_a3c7 = { f4 b5 [2] c6 97 [2] c0 a2 [2] ee a2 [2] d1 be }

  condition:
    any of them
}