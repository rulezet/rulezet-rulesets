rule TTP_XOR_MULT_DOSStub_c8c4 {
  strings:
    $key_c8c4 = { 9c ac [2] e8 b4 [2] af b6 [2] e8 a7 [2] a6 ab [2] aa a1 [2] bd aa [2] a6 e4 [2] 9b }

  condition:
    any of them
}