rule TTP_XOR_MULT_DOSStub_a5d2 {
  strings:
    $key_a5d2 = { f1 ba [2] 85 a2 [2] c2 a0 [2] 85 b1 [2] cb bd [2] c7 b7 [2] d0 bc [2] cb f2 [2] f6 }

  condition:
    any of them
}