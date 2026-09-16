rule TTP_XOR_MULT_DOSStub_8cc6 {
  strings:
    $key_8cc6 = { d8 ae [2] ac b6 [2] eb b4 [2] ac a5 [2] e2 a9 [2] ee a3 [2] f9 a8 [2] e2 e6 [2] df }

  condition:
    any of them
}