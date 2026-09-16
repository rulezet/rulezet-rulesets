rule TTP_XOR_MULT_DOSStub_1989 {
  strings:
    $key_1989 = { 4d e1 [2] 39 f9 [2] 7e fb [2] 39 ea [2] 77 e6 [2] 7b ec [2] 6c e7 [2] 77 a9 [2] 4a }

  condition:
    any of them
}