rule TTP_XOR_MULT_DOSStub_ab98 {
  strings:
    $key_ab98 = { ff f0 [2] 8b e8 [2] cc ea [2] 8b fb [2] c5 f7 [2] c9 fd [2] de f6 [2] c5 b8 [2] f8 }

  condition:
    any of them
}