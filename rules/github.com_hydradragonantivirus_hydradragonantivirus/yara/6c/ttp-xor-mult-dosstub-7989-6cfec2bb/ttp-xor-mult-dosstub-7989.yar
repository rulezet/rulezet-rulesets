rule TTP_XOR_MULT_DOSStub_7989 {
  strings:
    $key_7989 = { 2d e1 [2] 59 f9 [2] 1e fb [2] 59 ea [2] 17 e6 [2] 1b ec [2] 0c e7 [2] 17 a9 [2] 2a }

  condition:
    any of them
}