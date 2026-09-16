rule TTP_XOR_MULT_DOSStub_c887 {
  strings:
    $key_c887 = { 9c ef [2] e8 f7 [2] af f5 [2] e8 e4 [2] a6 e8 [2] aa e2 [2] bd e9 [2] a6 a7 [2] 9b }

  condition:
    any of them
}