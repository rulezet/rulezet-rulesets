rule TTP_XOR_MULT_DOSStub_8cc3 {
  strings:
    $key_8cc3 = { d8 ab [2] ac b3 [2] eb b1 [2] ac a0 [2] e2 ac [2] ee a6 [2] f9 ad [2] e2 e3 [2] df }

  condition:
    any of them
}