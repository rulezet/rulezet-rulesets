rule TTP_XOR_MULT_DOSStub_5889 {
  strings:
    $key_5889 = { 0c e1 [2] 78 f9 [2] 3f fb [2] 78 ea [2] 36 e6 [2] 3a ec [2] 2d e7 [2] 36 a9 [2] 0b }

  condition:
    any of them
}