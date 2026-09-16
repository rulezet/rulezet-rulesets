rule TTP_XOR_MULT_DOSStub_3192 {
  strings:
    $key_3192 = { 65 fa [2] 11 e2 [2] 56 e0 [2] 11 f1 [2] 5f fd [2] 53 f7 [2] 44 fc [2] 5f b2 [2] 62 }

  condition:
    any of them
}