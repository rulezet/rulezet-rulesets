rule TTP_XOR_MULT_DOSStub_e1d3 {
  strings:
    $key_e1d3 = { b5 bb [2] c1 a3 [2] 86 a1 [2] c1 b0 [2] 8f bc [2] 83 b6 [2] 94 bd [2] 8f f3 [2] b2 }

  condition:
    any of them
}