rule TTP_XOR_MULT_DOSStub_0498 {
  strings:
    $key_0498 = { 50 f0 [2] 24 e8 [2] 63 ea [2] 24 fb [2] 6a f7 [2] 66 fd [2] 71 f6 [2] 6a b8 [2] 57 }

  condition:
    any of them
}