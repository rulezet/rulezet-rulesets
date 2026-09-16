rule TTP_XOR_MULT_DOSStub_c896 {
  strings:
    $key_c896 = { 9c fe [2] e8 e6 [2] af e4 [2] e8 f5 [2] a6 f9 [2] aa f3 [2] bd f8 [2] a6 b6 [2] 9b }

  condition:
    any of them
}