rule TTP_XOR_MULT_DOSStub_1c89 {
  strings:
    $key_1c89 = { 48 e1 [2] 3c f9 [2] 7b fb [2] 3c ea [2] 72 e6 [2] 7e ec [2] 69 e7 [2] 72 a9 [2] 4f }

  condition:
    any of them
}