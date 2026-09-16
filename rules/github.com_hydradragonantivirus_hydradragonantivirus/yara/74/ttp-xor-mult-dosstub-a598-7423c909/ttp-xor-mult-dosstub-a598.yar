rule TTP_XOR_MULT_DOSStub_a598 {
  strings:
    $key_a598 = { f1 f0 [2] 85 e8 [2] c2 ea [2] 85 fb [2] cb f7 [2] c7 fd [2] d0 f6 [2] cb b8 [2] f6 }

  condition:
    any of them
}