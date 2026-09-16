rule TTP_XOR_MULT_DOSStub_a5da {
  strings:
    $key_a5da = { f1 b2 [2] 85 aa [2] c2 a8 [2] 85 b9 [2] cb b5 [2] c7 bf [2] d0 b4 [2] cb fa [2] f6 }

  condition:
    any of them
}