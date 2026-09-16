rule TTP_XOR_MULT_DOSStub_3b98 {
  strings:
    $key_3b98 = { 6f f0 [2] 1b e8 [2] 5c ea [2] 1b fb [2] 55 f7 [2] 59 fd [2] 4e f6 [2] 55 b8 [2] 68 }

  condition:
    any of them
}