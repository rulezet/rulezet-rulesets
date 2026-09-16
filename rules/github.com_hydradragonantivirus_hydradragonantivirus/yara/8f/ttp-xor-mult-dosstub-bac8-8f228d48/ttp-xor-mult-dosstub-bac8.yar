rule TTP_XOR_MULT_DOSStub_bac8 {
  strings:
    $key_bac8 = { ee a0 [2] 9a b8 [2] dd ba [2] 9a ab [2] d4 a7 [2] d8 ad [2] cf a6 [2] d4 e8 [2] e9 }

  condition:
    any of them
}