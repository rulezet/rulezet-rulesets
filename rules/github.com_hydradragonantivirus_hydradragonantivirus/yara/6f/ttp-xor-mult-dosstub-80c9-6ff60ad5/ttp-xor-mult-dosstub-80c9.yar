rule TTP_XOR_MULT_DOSStub_80c9 {
  strings:
    $key_80c9 = { d4 a1 [2] a0 b9 [2] e7 bb [2] a0 aa [2] ee a6 [2] e2 ac [2] f5 a7 [2] ee e9 [2] d3 }

  condition:
    any of them
}