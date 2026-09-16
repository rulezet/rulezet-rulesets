rule TTP_XOR_MULT_DOSStub_0c98 {
  strings:
    $key_0c98 = { 58 f0 [2] 2c e8 [2] 6b ea [2] 2c fb [2] 62 f7 [2] 6e fd [2] 79 f6 [2] 62 b8 [2] 5f }

  condition:
    any of them
}