rule TTP_XOR_MULT_DOSStub_a5c7 {
  strings:
    $key_a5c7 = { f1 af [2] 85 b7 [2] c2 b5 [2] 85 a4 [2] cb a8 [2] c7 a2 [2] d0 a9 [2] cb e7 [2] f6 }

  condition:
    any of them
}