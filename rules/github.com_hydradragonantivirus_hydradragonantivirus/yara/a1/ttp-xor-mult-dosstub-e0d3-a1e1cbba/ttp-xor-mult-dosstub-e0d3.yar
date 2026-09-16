rule TTP_XOR_MULT_DOSStub_e0d3 {
  strings:
    $key_e0d3 = { b4 bb [2] c0 a3 [2] 87 a1 [2] c0 b0 [2] 8e bc [2] 82 b6 [2] 95 bd [2] 8e f3 [2] b3 }

  condition:
    any of them
}