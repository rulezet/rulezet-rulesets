rule TTP_XOR_MULT_DOSStub_8cc5 {
  strings:
    $key_8cc5 = { d8 ad [2] ac b5 [2] eb b7 [2] ac a6 [2] e2 aa [2] ee a0 [2] f9 ab [2] e2 e5 [2] df }

  condition:
    any of them
}