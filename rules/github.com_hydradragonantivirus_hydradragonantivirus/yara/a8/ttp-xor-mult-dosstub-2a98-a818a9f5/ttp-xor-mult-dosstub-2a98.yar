rule TTP_XOR_MULT_DOSStub_2a98 {
  strings:
    $key_2a98 = { 7e f0 [2] 0a e8 [2] 4d ea [2] 0a fb [2] 44 f7 [2] 48 fd [2] 5f f6 [2] 44 b8 [2] 79 }

  condition:
    any of them
}