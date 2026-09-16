rule TTP_XOR_MULT_DOSStub_a5b4 {
  strings:
    $key_a5b4 = { f1 dc [2] 85 c4 [2] c2 c6 [2] 85 d7 [2] cb db [2] c7 d1 [2] d0 da [2] cb 94 [2] f6 }

  condition:
    any of them
}