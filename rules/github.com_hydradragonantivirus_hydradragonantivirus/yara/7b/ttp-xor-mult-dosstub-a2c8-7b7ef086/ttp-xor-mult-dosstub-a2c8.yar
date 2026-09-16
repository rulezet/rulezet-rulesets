rule TTP_XOR_MULT_DOSStub_a2c8 {
  strings:
    $key_a2c8 = { f6 a0 [2] 82 b8 [2] c5 ba [2] 82 ab [2] cc a7 [2] c0 ad [2] d7 a6 [2] cc e8 [2] f1 }

  condition:
    any of them
}