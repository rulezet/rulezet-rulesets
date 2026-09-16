rule TTP_XOR_MULT_DOSStub_80ca {
  strings:
    $key_80ca = { d4 a2 [2] a0 ba [2] e7 b8 [2] a0 a9 [2] ee a5 [2] e2 af [2] f5 a4 [2] ee ea [2] d3 }

  condition:
    any of them
}