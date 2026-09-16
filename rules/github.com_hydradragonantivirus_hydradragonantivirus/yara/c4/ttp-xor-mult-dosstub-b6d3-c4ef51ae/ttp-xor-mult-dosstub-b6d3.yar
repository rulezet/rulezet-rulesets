rule TTP_XOR_MULT_DOSStub_b6d3 {
  strings:
    $key_b6d3 = { e2 bb [2] 96 a3 [2] d1 a1 [2] 96 b0 [2] d8 bc [2] d4 b6 [2] c3 bd [2] d8 f3 [2] e5 }

  condition:
    any of them
}