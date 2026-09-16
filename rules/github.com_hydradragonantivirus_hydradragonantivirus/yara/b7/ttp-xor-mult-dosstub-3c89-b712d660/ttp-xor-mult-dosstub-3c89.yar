rule TTP_XOR_MULT_DOSStub_3c89 {
  strings:
    $key_3c89 = { 68 e1 [2] 1c f9 [2] 5b fb [2] 1c ea [2] 52 e6 [2] 5e ec [2] 49 e7 [2] 52 a9 [2] 6f }

  condition:
    any of them
}