rule TTP_XOR_MULT_DOSStub_1a96 {
  strings:
    $key_1a96 = { 4e fe [2] 3a e6 [2] 7d e4 [2] 3a f5 [2] 74 f9 [2] 78 f3 [2] 6f f8 [2] 74 b6 [2] 49 }

  condition:
    any of them
}