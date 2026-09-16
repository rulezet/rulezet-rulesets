rule TTP_XOR_MULT_DOSStub_4e96 {
  strings:
    $key_4e96 = { 1a fe [2] 6e e6 [2] 29 e4 [2] 6e f5 [2] 20 f9 [2] 2c f3 [2] 3b f8 [2] 20 b6 [2] 1d }

  condition:
    any of them
}