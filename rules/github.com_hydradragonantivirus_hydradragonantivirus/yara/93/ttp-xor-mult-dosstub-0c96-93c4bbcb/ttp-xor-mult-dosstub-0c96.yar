rule TTP_XOR_MULT_DOSStub_0c96 {
  strings:
    $key_0c96 = { 58 fe [2] 2c e6 [2] 6b e4 [2] 2c f5 [2] 62 f9 [2] 6e f3 [2] 79 f8 [2] 62 b6 [2] 5f }

  condition:
    any of them
}