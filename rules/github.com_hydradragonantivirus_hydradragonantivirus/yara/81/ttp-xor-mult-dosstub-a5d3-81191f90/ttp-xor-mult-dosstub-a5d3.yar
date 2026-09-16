rule TTP_XOR_MULT_DOSStub_a5d3 {
  strings:
    $key_a5d3 = { f1 bb [2] 85 a3 [2] c2 a1 [2] 85 b0 [2] cb bc [2] c7 b6 [2] d0 bd [2] cb f3 [2] f6 }

  condition:
    any of them
}