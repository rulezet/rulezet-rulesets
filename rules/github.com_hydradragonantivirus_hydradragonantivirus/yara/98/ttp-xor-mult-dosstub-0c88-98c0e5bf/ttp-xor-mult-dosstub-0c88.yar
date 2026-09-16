rule TTP_XOR_MULT_DOSStub_0c88 {
  strings:
    $key_0c88 = { 58 e0 [2] 2c f8 [2] 6b fa [2] 2c eb [2] 62 e7 [2] 6e ed [2] 79 e6 [2] 62 a8 [2] 5f }

  condition:
    any of them
}