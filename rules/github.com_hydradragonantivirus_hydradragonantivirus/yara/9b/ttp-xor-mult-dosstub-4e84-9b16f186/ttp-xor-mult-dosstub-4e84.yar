rule TTP_XOR_MULT_DOSStub_4e84 {
  strings:
    $key_4e84 = { 1a ec [2] 6e f4 [2] 29 f6 [2] 6e e7 [2] 20 eb [2] 2c e1 [2] 3b ea [2] 20 a4 [2] 1d }

  condition:
    any of them
}