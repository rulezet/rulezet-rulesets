rule TTP_XOR_MULT_DOSStub_0c92 {
  strings:
    $key_0c92 = { 58 fa [2] 2c e2 [2] 6b e0 [2] 2c f1 [2] 62 fd [2] 6e f7 [2] 79 fc [2] 62 b2 [2] 5f }

  condition:
    any of them
}