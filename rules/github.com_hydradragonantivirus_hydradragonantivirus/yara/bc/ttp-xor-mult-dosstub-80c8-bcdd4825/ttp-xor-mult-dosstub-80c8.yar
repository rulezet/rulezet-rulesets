rule TTP_XOR_MULT_DOSStub_80c8 {
  strings:
    $key_80c8 = { d4 a0 [2] a0 b8 [2] e7 ba [2] a0 ab [2] ee a7 [2] e2 ad [2] f5 a6 [2] ee e8 [2] d3 }

  condition:
    any of them
}