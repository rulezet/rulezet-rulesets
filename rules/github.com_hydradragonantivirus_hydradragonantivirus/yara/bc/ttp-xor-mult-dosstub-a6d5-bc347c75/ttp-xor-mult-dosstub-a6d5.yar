rule TTP_XOR_MULT_DOSStub_a6d5 {
  strings:
    $key_a6d5 = { f2 bd [2] 86 a5 [2] c1 a7 [2] 86 b6 [2] c8 ba [2] c4 b0 [2] d3 bb [2] c8 f5 [2] f5 }

  condition:
    any of them
}