rule TTP_XOR_MULT_DOSStub_0a98 {
  strings:
    $key_0a98 = { 5e f0 [2] 2a e8 [2] 6d ea [2] 2a fb [2] 64 f7 [2] 68 fd [2] 7f f6 [2] 64 b8 [2] 59 }

  condition:
    any of them
}