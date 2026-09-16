rule TTP_XOR_MULT_DOSStub_428b {
  strings:
    $key_428b = { 16 e3 [2] 62 fb [2] 25 f9 [2] 62 e8 [2] 2c e4 [2] 20 ee [2] 37 e5 [2] 2c ab [2] 11 }

  condition:
    any of them
}