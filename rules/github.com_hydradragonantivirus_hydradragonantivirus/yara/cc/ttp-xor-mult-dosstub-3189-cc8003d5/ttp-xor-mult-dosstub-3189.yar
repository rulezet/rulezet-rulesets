rule TTP_XOR_MULT_DOSStub_3189 {
  strings:
    $key_3189 = { 65 e1 [2] 11 f9 [2] 56 fb [2] 11 ea [2] 5f e6 [2] 53 ec [2] 44 e7 [2] 5f a9 [2] 62 }

  condition:
    any of them
}