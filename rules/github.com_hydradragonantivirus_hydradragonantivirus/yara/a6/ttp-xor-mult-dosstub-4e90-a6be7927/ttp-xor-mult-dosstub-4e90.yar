rule TTP_XOR_MULT_DOSStub_4e90 {
  strings:
    $key_4e90 = { 1a f8 [2] 6e e0 [2] 29 e2 [2] 6e f3 [2] 20 ff [2] 2c f5 [2] 3b fe [2] 20 b0 [2] 1d }

  condition:
    any of them
}