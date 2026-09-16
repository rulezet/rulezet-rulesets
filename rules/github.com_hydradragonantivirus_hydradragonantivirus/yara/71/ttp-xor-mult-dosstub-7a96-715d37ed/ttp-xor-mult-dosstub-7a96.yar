rule TTP_XOR_MULT_DOSStub_7a96 {
  strings:
    $key_7a96 = { 2e fe [2] 5a e6 [2] 1d e4 [2] 5a f5 [2] 14 f9 [2] 18 f3 [2] 0f f8 [2] 14 b6 [2] 29 }

  condition:
    any of them
}