rule TTP_XOR_MULT_DOSStub_bac9 {
  strings:
    $key_bac9 = { ee a1 [2] 9a b9 [2] dd bb [2] 9a aa [2] d4 a6 [2] d8 ac [2] cf a7 [2] d4 e9 [2] e9 }

  condition:
    any of them
}