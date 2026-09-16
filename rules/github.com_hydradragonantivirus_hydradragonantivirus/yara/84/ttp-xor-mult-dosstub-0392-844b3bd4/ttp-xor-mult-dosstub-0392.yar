rule TTP_XOR_MULT_DOSStub_0392 {
  strings:
    $key_0392 = { 57 fa [2] 23 e2 [2] 64 e0 [2] 23 f1 [2] 6d fd [2] 61 f7 [2] 76 fc [2] 6d b2 [2] 50 }

  condition:
    any of them
}