rule TTP_XOR_MULT_DOSStub_5997 {
  strings:
    $key_5997 = { 0d ff [2] 79 e7 [2] 3e e5 [2] 79 f4 [2] 37 f8 [2] 3b f2 [2] 2c f9 [2] 37 b7 [2] 0a }

  condition:
    any of them
}