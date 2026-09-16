rule TTP_XOR_MULT_DOSStub_c7d3 {
  strings:
    $key_c7d3 = { 93 bb [2] e7 a3 [2] a0 a1 [2] e7 b0 [2] a9 bc [2] a5 b6 [2] b2 bd [2] a9 f3 [2] 94 }

  condition:
    any of them
}