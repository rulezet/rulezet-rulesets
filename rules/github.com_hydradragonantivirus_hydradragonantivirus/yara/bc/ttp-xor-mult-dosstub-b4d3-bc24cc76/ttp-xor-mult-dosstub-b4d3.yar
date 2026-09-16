rule TTP_XOR_MULT_DOSStub_b4d3 {
  strings:
    $key_b4d3 = { e0 bb [2] 94 a3 [2] d3 a1 [2] 94 b0 [2] da bc [2] d6 b6 [2] c1 bd [2] da f3 [2] e7 }

  condition:
    any of them
}