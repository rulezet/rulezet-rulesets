rule TTP_XOR_MULT_DOSStub_3398 {
  strings:
    $key_3398 = { 67 f0 [2] 13 e8 [2] 54 ea [2] 13 fb [2] 5d f7 [2] 51 fd [2] 46 f6 [2] 5d b8 [2] 60 }

  condition:
    any of them
}