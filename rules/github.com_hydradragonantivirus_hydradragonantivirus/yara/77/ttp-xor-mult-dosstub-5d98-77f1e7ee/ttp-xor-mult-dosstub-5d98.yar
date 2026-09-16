rule TTP_XOR_MULT_DOSStub_5d98 {
  strings:
    $key_5d98 = { 09 f0 [2] 7d e8 [2] 3a ea [2] 7d fb [2] 33 f7 [2] 3f fd [2] 28 f6 [2] 33 b8 [2] 0e }

  condition:
    any of them
}