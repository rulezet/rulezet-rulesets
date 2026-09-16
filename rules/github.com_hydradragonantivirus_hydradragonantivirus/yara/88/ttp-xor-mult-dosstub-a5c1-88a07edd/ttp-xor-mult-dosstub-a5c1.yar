rule TTP_XOR_MULT_DOSStub_a5c1 {
  strings:
    $key_a5c1 = { f1 a9 [2] 85 b1 [2] c2 b3 [2] 85 a2 [2] cb ae [2] c7 a4 [2] d0 af [2] cb e1 [2] f6 }

  condition:
    any of them
}