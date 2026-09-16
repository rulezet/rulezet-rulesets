rule TTP_XOR_MULT_DOSStub_a6d4 {
  strings:
    $key_a6d4 = { f2 bc [2] 86 a4 [2] c1 a6 [2] 86 b7 [2] c8 bb [2] c4 b1 [2] d3 ba [2] c8 f4 [2] f5 }

  condition:
    any of them
}