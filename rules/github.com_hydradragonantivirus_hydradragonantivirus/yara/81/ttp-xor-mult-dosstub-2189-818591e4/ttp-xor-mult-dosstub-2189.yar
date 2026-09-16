rule TTP_XOR_MULT_DOSStub_2189 {
  strings:
    $key_2189 = { 75 e1 [2] 01 f9 [2] 46 fb [2] 01 ea [2] 4f e6 [2] 43 ec [2] 54 e7 [2] 4f a9 [2] 72 }

  condition:
    any of them
}