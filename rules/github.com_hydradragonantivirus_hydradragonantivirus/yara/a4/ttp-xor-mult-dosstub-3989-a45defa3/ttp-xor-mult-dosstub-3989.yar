rule TTP_XOR_MULT_DOSStub_3989 {
  strings:
    $key_3989 = { 6d e1 [2] 19 f9 [2] 5e fb [2] 19 ea [2] 57 e6 [2] 5b ec [2] 4c e7 [2] 57 a9 [2] 6a }

  condition:
    any of them
}