rule TTP_XOR_MULT_DOSStub_4389 {
  strings:
    $key_4389 = { 17 e1 [2] 63 f9 [2] 24 fb [2] 63 ea [2] 2d e6 [2] 21 ec [2] 36 e7 [2] 2d a9 [2] 10 }

  condition:
    any of them
}