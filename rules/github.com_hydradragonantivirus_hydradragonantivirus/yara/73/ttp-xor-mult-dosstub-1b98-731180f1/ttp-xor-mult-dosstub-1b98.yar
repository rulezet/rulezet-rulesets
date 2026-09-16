rule TTP_XOR_MULT_DOSStub_1b98 {
  strings:
    $key_1b98 = { 4f f0 [2] 3b e8 [2] 7c ea [2] 3b fb [2] 75 f7 [2] 79 fd [2] 6e f6 [2] 75 b8 [2] 48 }

  condition:
    any of them
}