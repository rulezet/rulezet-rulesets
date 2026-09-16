rule TTP_XOR_MULT_DOSStub_c895 {
  strings:
    $key_c895 = { 9c fd [2] e8 e5 [2] af e7 [2] e8 f6 [2] a6 fa [2] aa f0 [2] bd fb [2] a6 b5 [2] 9b }

  condition:
    any of them
}