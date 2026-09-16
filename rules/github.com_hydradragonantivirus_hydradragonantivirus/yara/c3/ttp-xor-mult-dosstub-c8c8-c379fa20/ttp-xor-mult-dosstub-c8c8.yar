rule TTP_XOR_MULT_DOSStub_c8c8 {
  strings:
    $key_c8c8 = { 9c a0 [2] e8 b8 [2] af ba [2] e8 ab [2] a6 a7 [2] aa ad [2] bd a6 [2] a6 e8 [2] 9b }

  condition:
    any of them
}