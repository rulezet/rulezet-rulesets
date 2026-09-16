rule TTP_XOR_MULT_DOSStub_89da {
  strings:
    $key_89da = { dd b2 [2] a9 aa [2] ee a8 [2] a9 b9 [2] e7 b5 [2] eb bf [2] fc b4 [2] e7 fa [2] da }

  condition:
    any of them
}