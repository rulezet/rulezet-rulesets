rule TTP_XOR_MULT_DOSStub_7089 {
  strings:
    $key_7089 = { 24 e1 [2] 50 f9 [2] 17 fb [2] 50 ea [2] 1e e6 [2] 12 ec [2] 05 e7 [2] 1e a9 [2] 23 }

  condition:
    any of them
}