rule TTP_XOR_MULT_DOSStub_89d6 {
  strings:
    $key_89d6 = { dd be [2] a9 a6 [2] ee a4 [2] a9 b5 [2] e7 b9 [2] eb b3 [2] fc b8 [2] e7 f6 [2] da }

  condition:
    any of them
}