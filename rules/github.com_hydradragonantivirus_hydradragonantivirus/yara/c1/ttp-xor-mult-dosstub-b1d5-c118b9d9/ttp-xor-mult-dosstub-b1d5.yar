rule TTP_XOR_MULT_DOSStub_b1d5 {
  strings:
    $key_b1d5 = { e5 bd [2] 91 a5 [2] d6 a7 [2] 91 b6 [2] df ba [2] d3 b0 [2] c4 bb [2] df f5 [2] e2 }

  condition:
    any of them
}