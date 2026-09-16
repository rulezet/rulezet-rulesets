rule TTP_XOR_MULT_DOSStub_89d1 {
  strings:
    $key_89d1 = { dd b9 [2] a9 a1 [2] ee a3 [2] a9 b2 [2] e7 be [2] eb b4 [2] fc bf [2] e7 f1 [2] da }

  condition:
    any of them
}