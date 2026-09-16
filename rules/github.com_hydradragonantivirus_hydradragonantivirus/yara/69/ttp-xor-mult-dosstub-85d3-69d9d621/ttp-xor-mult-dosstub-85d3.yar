rule TTP_XOR_MULT_DOSStub_85d3 {
  strings:
    $key_85d3 = { d1 bb [2] a5 a3 [2] e2 a1 [2] a5 b0 [2] eb bc [2] e7 b6 [2] f0 bd [2] eb f3 [2] d6 }

  condition:
    any of them
}