rule TTP_XOR_MULT_DOSStub_a6c3 {
  strings:
    $key_a6c3 = { f2 ab [2] 86 b3 [2] c1 b1 [2] 86 a0 [2] c8 ac [2] c4 a6 [2] d3 ad [2] c8 e3 [2] f5 }

  condition:
    any of them
}