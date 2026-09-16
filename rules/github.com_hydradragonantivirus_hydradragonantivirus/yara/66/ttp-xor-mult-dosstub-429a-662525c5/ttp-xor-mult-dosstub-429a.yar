rule TTP_XOR_MULT_DOSStub_429a {
  strings:
    $key_429a = { 16 f2 [2] 62 ea [2] 25 e8 [2] 62 f9 [2] 2c f5 [2] 20 ff [2] 37 f4 [2] 2c ba [2] 11 }

  condition:
    any of them
}