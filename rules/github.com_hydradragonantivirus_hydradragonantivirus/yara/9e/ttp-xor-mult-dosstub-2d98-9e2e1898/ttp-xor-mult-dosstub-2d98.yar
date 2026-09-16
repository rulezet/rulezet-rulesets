rule TTP_XOR_MULT_DOSStub_2d98 {
  strings:
    $key_2d98 = { 79 f0 [2] 0d e8 [2] 4a ea [2] 0d fb [2] 43 f7 [2] 4f fd [2] 58 f6 [2] 43 b8 [2] 7e }

  condition:
    any of them
}