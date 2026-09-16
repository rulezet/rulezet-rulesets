rule TTP_XOR_MULT_DOSStub_bac0 {
  strings:
    $key_bac0 = { ee a8 [2] 9a b0 [2] dd b2 [2] 9a a3 [2] d4 af [2] d8 a5 [2] cf ae [2] d4 e0 [2] e9 }

  condition:
    any of them
}