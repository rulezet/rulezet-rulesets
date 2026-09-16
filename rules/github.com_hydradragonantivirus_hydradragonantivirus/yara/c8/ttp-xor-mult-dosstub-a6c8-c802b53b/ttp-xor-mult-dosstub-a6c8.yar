rule TTP_XOR_MULT_DOSStub_a6c8 {
  strings:
    $key_a6c8 = { f2 a0 [2] 86 b8 [2] c1 ba [2] 86 ab [2] c8 a7 [2] c4 ad [2] d3 a6 [2] c8 e8 [2] f5 }

  condition:
    any of them
}