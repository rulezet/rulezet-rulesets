rule TTP_XOR_MULT_DOSStub_b4d5 {
  strings:
    $key_b4d5 = { e0 bd [2] 94 a5 [2] d3 a7 [2] 94 b6 [2] da ba [2] d6 b0 [2] c1 bb [2] da f5 [2] e7 }

  condition:
    any of them
}