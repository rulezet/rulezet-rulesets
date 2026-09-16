rule TTP_XOR_MULT_DOSStub_89d3 {
  strings:
    $key_89d3 = { dd bb [2] a9 a3 [2] ee a1 [2] a9 b0 [2] e7 bc [2] eb b6 [2] fc bd [2] e7 f3 [2] da }

  condition:
    any of them
}