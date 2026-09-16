rule TTP_XOR_MULT_DOSStub_0c9a {
  strings:
    $key_0c9a = { 58 f2 [2] 2c ea [2] 6b e8 [2] 2c f9 [2] 62 f5 [2] 6e ff [2] 79 f4 [2] 62 ba [2] 5f }

  condition:
    any of them
}