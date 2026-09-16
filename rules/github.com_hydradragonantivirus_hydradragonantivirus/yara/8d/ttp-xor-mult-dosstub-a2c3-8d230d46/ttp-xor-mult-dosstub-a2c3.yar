rule TTP_XOR_MULT_DOSStub_a2c3 {
  strings:
    $key_a2c3 = { f6 ab [2] 82 b3 [2] c5 b1 [2] 82 a0 [2] cc ac [2] c0 a6 [2] d7 ad [2] cc e3 [2] f1 }

  condition:
    any of them
}