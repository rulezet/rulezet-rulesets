rule TTP_XOR_MULT_DOSStub_a5d0 {
  strings:
    $key_a5d0 = { f1 b8 [2] 85 a0 [2] c2 a2 [2] 85 b3 [2] cb bf [2] c7 b5 [2] d0 be [2] cb f0 [2] f6 }

  condition:
    any of them
}