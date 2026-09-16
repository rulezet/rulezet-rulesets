rule TTP_XOR_MULT_DOSStub_4392 {
  strings:
    $key_4392 = { 17 fa [2] 63 e2 [2] 24 e0 [2] 63 f1 [2] 2d fd [2] 21 f7 [2] 36 fc [2] 2d b2 [2] 10 }

  condition:
    any of them
}