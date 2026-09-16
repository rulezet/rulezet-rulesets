rule TTP_XOR_MULT_DOSStub_5996 {
  strings:
    $key_5996 = { 0d fe [2] 79 e6 [2] 3e e4 [2] 79 f5 [2] 37 f9 [2] 3b f3 [2] 2c f8 [2] 37 b6 [2] 0a }

  condition:
    any of them
}