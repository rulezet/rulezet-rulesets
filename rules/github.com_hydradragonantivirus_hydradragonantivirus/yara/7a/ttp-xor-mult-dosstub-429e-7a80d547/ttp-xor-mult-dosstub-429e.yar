rule TTP_XOR_MULT_DOSStub_429e {
  strings:
    $key_429e = { 16 f6 [2] 62 ee [2] 25 ec [2] 62 fd [2] 2c f1 [2] 20 fb [2] 37 f0 [2] 2c be [2] 11 }

  condition:
    any of them
}