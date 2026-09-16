rule TTP_XOR_MULT_DOSStub_0d98 {
  strings:
    $key_0d98 = { 59 f0 [2] 2d e8 [2] 6a ea [2] 2d fb [2] 63 f7 [2] 6f fd [2] 78 f6 [2] 63 b8 [2] 5e }

  condition:
    any of them
}