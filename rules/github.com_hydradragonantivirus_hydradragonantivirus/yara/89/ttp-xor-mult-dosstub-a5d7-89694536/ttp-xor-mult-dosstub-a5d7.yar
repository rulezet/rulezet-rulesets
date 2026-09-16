rule TTP_XOR_MULT_DOSStub_a5d7 {
  strings:
    $key_a5d7 = { f1 bf [2] 85 a7 [2] c2 a5 [2] 85 b4 [2] cb b8 [2] c7 b2 [2] d0 b9 [2] cb f7 [2] f6 }

  condition:
    any of them
}