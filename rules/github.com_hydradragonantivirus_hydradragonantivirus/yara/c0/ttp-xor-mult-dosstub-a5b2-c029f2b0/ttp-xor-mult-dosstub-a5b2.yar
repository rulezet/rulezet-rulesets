rule TTP_XOR_MULT_DOSStub_a5b2 {
  strings:
    $key_a5b2 = { f1 da [2] 85 c2 [2] c2 c0 [2] 85 d1 [2] cb dd [2] c7 d7 [2] d0 dc [2] cb 92 [2] f6 }

  condition:
    any of them
}