rule TTP_XOR_MULT_DOSStub_a5c8 {
  strings:
    $key_a5c8 = { f1 a0 [2] 85 b8 [2] c2 ba [2] 85 ab [2] cb a7 [2] c7 ad [2] d0 a6 [2] cb e8 [2] f6 }

  condition:
    any of them
}