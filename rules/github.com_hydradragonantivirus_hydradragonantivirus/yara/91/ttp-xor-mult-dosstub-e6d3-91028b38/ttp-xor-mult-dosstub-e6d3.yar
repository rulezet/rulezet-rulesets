rule TTP_XOR_MULT_DOSStub_e6d3 {
  strings:
    $key_e6d3 = { b2 bb [2] c6 a3 [2] 81 a1 [2] c6 b0 [2] 88 bc [2] 84 b6 [2] 93 bd [2] 88 f3 [2] b5 }

  condition:
    any of them
}