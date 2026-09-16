rule TTP_XOR_MULT_DOSStub_a5d1 {
  strings:
    $key_a5d1 = { f1 b9 [2] 85 a1 [2] c2 a3 [2] 85 b2 [2] cb be [2] c7 b4 [2] d0 bf [2] cb f1 [2] f6 }

  condition:
    any of them
}