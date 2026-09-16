rule TTP_XOR_MULT_DOSStub_0c84 {
  strings:
    $key_0c84 = { 58 ec [2] 2c f4 [2] 6b f6 [2] 2c e7 [2] 62 eb [2] 6e e1 [2] 79 ea [2] 62 a4 [2] 5f }

  condition:
    any of them
}