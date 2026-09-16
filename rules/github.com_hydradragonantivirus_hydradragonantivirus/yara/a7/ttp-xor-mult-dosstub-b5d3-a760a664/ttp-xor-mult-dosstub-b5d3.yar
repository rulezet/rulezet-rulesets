rule TTP_XOR_MULT_DOSStub_b5d3 {
  strings:
    $key_b5d3 = { e1 bb [2] 95 a3 [2] d2 a1 [2] 95 b0 [2] db bc [2] d7 b6 [2] c0 bd [2] db f3 [2] e6 }

  condition:
    any of them
}