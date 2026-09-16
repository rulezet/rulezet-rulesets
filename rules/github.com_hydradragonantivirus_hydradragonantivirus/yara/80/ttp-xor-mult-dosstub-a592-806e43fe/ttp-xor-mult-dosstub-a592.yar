rule TTP_XOR_MULT_DOSStub_a592 {
  strings:
    $key_a592 = { f1 fa [2] 85 e2 [2] c2 e0 [2] 85 f1 [2] cb fd [2] c7 f7 [2] d0 fc [2] cb b2 [2] f6 }

  condition:
    any of them
}