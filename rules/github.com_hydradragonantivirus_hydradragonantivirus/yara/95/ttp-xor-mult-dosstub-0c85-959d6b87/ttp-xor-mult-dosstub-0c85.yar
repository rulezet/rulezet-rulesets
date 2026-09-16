rule TTP_XOR_MULT_DOSStub_0c85 {
  strings:
    $key_0c85 = { 58 ed [2] 2c f5 [2] 6b f7 [2] 2c e6 [2] 62 ea [2] 6e e0 [2] 79 eb [2] 62 a5 [2] 5f }

  condition:
    any of them
}