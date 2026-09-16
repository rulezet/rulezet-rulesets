rule TTP_XOR_MULT_DOSStub_e7d3 {
  strings:
    $key_e7d3 = { b3 bb [2] c7 a3 [2] 80 a1 [2] c7 b0 [2] 89 bc [2] 85 b6 [2] 92 bd [2] 89 f3 [2] b4 }

  condition:
    any of them
}