rule TTP_XOR_MULT_DOSStub_0c94 {
  strings:
    $key_0c94 = { 58 fc [2] 2c e4 [2] 6b e6 [2] 2c f7 [2] 62 fb [2] 6e f1 [2] 79 fa [2] 62 b4 [2] 5f }

  condition:
    any of them
}