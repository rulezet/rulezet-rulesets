rule TTP_XOR_MULT_DOSStub_c882 {
  strings:
    $key_c882 = { 9c ea [2] e8 f2 [2] af f0 [2] e8 e1 [2] a6 ed [2] aa e7 [2] bd ec [2] a6 a2 [2] 9b }

  condition:
    any of them
}