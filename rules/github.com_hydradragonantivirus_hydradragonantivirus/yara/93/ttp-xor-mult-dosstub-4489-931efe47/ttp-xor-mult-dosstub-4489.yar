rule TTP_XOR_MULT_DOSStub_4489 {
  strings:
    $key_4489 = { 10 e1 [2] 64 f9 [2] 23 fb [2] 64 ea [2] 2a e6 [2] 26 ec [2] 31 e7 [2] 2a a9 [2] 17 }

  condition:
    any of them
}