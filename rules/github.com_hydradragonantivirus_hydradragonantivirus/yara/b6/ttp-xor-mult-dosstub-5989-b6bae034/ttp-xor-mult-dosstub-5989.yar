rule TTP_XOR_MULT_DOSStub_5989 {
  strings:
    $key_5989 = { 0d e1 [2] 79 f9 [2] 3e fb [2] 79 ea [2] 37 e6 [2] 3b ec [2] 2c e7 [2] 37 a9 [2] 0a }

  condition:
    any of them
}