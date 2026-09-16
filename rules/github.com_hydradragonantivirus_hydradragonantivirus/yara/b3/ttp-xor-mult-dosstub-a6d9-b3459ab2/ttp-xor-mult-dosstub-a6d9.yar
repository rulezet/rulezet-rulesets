rule TTP_XOR_MULT_DOSStub_a6d9 {
  strings:
    $key_a6d9 = { f2 b1 [2] 86 a9 [2] c1 ab [2] 86 ba [2] c8 b6 [2] c4 bc [2] d3 b7 [2] c8 f9 [2] f5 }

  condition:
    any of them
}