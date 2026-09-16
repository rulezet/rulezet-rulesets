rule TTP_XOR_MULT_DOSStub_7889 {
  strings:
    $key_7889 = { 2c e1 [2] 58 f9 [2] 1f fb [2] 58 ea [2] 16 e6 [2] 1a ec [2] 0d e7 [2] 16 a9 [2] 2b }

  condition:
    any of them
}