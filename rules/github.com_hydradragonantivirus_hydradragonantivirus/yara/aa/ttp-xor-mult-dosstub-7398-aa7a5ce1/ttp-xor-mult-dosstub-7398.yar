rule TTP_XOR_MULT_DOSStub_7398 {
  strings:
    $key_7398 = { 27 f0 [2] 53 e8 [2] 14 ea [2] 53 fb [2] 1d f7 [2] 11 fd [2] 06 f6 [2] 1d b8 [2] 20 }

  condition:
    any of them
}