rule TTP_XOR_MULT_DOSStub_0792 {
  strings:
    $key_0792 = { 53 fa [2] 27 e2 [2] 60 e0 [2] 27 f1 [2] 69 fd [2] 65 f7 [2] 72 fc [2] 69 b2 [2] 54 }

  condition:
    any of them
}