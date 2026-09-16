rule TTP_XOR_MULT_DOSStub_7189 {
  strings:
    $key_7189 = { 25 e1 [2] 51 f9 [2] 16 fb [2] 51 ea [2] 1f e6 [2] 13 ec [2] 04 e7 [2] 1f a9 [2] 22 }

  condition:
    any of them
}