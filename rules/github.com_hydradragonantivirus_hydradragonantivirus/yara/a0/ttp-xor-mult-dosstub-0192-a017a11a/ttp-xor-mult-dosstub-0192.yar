rule TTP_XOR_MULT_DOSStub_0192 {
  strings:
    $key_0192 = { 55 fa [2] 21 e2 [2] 66 e0 [2] 21 f1 [2] 6f fd [2] 63 f7 [2] 74 fc [2] 6f b2 [2] 52 }

  condition:
    any of them
}