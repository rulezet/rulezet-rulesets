rule TTP_XOR_MULT_DOSStub_3a98 {
  strings:
    $key_3a98 = { 6e f0 [2] 1a e8 [2] 5d ea [2] 1a fb [2] 54 f7 [2] 58 fd [2] 4f f6 [2] 54 b8 [2] 69 }

  condition:
    any of them
}