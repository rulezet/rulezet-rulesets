rule TTP_XOR_MULT_DOSStub_0398 {
  strings:
    $key_0398 = { 57 f0 [2] 23 e8 [2] 64 ea [2] 23 fb [2] 6d f7 [2] 61 fd [2] 76 f6 [2] 6d b8 [2] 50 }

  condition:
    any of them
}