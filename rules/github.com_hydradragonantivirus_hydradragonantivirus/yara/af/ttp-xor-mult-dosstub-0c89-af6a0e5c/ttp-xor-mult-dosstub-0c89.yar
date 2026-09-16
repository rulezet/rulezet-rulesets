rule TTP_XOR_MULT_DOSStub_0c89 {
  strings:
    $key_0c89 = { 58 e1 [2] 2c f9 [2] 6b fb [2] 2c ea [2] 62 e6 [2] 6e ec [2] 79 e7 [2] 62 a9 [2] 5f }

  condition:
    any of them
}