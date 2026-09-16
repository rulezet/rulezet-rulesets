rule TTP_XOR_MULT_DOSStub_89d5 {
  strings:
    $key_89d5 = { dd bd [2] a9 a5 [2] ee a7 [2] a9 b6 [2] e7 ba [2] eb b0 [2] fc bb [2] e7 f5 [2] da }

  condition:
    any of them
}