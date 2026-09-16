rule TTP_XOR_MULT_DOSStub_429b {
  strings:
    $key_429b = { 16 f3 [2] 62 eb [2] 25 e9 [2] 62 f8 [2] 2c f4 [2] 20 fe [2] 37 f5 [2] 2c bb [2] 11 }

  condition:
    any of them
}