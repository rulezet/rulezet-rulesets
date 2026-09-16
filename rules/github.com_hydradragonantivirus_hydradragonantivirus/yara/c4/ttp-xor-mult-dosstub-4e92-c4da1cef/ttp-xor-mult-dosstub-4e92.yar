rule TTP_XOR_MULT_DOSStub_4e92 {
  strings:
    $key_4e92 = { 1a fa [2] 6e e2 [2] 29 e0 [2] 6e f1 [2] 20 fd [2] 2c f7 [2] 3b fc [2] 20 b2 [2] 1d }

  condition:
    any of them
}