rule TTP_XOR_MULT_DOSStub_0c95 {
  strings:
    $key_0c95 = { 58 fd [2] 2c e5 [2] 6b e7 [2] 2c f6 [2] 62 fa [2] 6e f0 [2] 79 fb [2] 62 b5 [2] 5f }

  condition:
    any of them
}