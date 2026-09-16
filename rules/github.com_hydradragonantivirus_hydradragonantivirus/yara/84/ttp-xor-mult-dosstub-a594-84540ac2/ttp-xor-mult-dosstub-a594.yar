rule TTP_XOR_MULT_DOSStub_a594 {
  strings:
    $key_a594 = { f1 fc [2] 85 e4 [2] c2 e6 [2] 85 f7 [2] cb fb [2] c7 f1 [2] d0 fa [2] cb b4 [2] f6 }

  condition:
    any of them
}