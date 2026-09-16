rule TTP_XOR_MULT_DOSStub_6a98 {
  strings:
    $key_6a98 = { 3e f0 [2] 4a e8 [2] 0d ea [2] 4a fb [2] 04 f7 [2] 08 fd [2] 1f f6 [2] 04 b8 [2] 39 }

  condition:
    any of them
}