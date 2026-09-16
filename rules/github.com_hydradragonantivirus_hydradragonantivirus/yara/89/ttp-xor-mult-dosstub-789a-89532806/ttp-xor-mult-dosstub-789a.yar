rule TTP_XOR_MULT_DOSStub_789a {
  strings:
    $key_789a = { 2c f2 [2] 58 ea [2] 1f e8 [2] 58 f9 [2] 16 f5 [2] 1a ff [2] 0d f4 [2] 16 ba [2] 2b }

  condition:
    any of them
}