rule TTP_XOR_MULT_DOSStub_4b98 {
  strings:
    $key_4b98 = { 1f f0 [2] 6b e8 [2] 2c ea [2] 6b fb [2] 25 f7 [2] 29 fd [2] 3e f6 [2] 25 b8 [2] 18 }

  condition:
    any of them
}