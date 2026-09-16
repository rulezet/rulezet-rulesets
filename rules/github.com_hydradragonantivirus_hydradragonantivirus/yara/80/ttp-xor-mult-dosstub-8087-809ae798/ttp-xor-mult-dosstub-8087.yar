rule TTP_XOR_MULT_DOSStub_8087 {
  strings:
    $key_8087 = { d4 ef [2] a0 f7 [2] e7 f5 [2] a0 e4 [2] ee e8 [2] e2 e2 [2] f5 e9 [2] ee a7 [2] d3 }

  condition:
    any of them
}