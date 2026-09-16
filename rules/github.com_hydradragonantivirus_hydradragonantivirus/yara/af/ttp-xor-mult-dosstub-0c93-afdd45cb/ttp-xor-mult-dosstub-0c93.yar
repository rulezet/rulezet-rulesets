rule TTP_XOR_MULT_DOSStub_0c93 {
  strings:
    $key_0c93 = { 58 fb [2] 2c e3 [2] 6b e1 [2] 2c f0 [2] 62 fc [2] 6e f6 [2] 79 fd [2] 62 b3 [2] 5f }

  condition:
    any of them
}