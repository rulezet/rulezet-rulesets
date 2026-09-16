rule TTP_XOR_MULT_DOSStub_3d98 {
  strings:
    $key_3d98 = { 69 f0 [2] 1d e8 [2] 5a ea [2] 1d fb [2] 53 f7 [2] 5f fd [2] 48 f6 [2] 53 b8 [2] 6e }

  condition:
    any of them
}