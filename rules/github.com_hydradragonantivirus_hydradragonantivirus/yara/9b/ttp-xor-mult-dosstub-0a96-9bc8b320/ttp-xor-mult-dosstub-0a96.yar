rule TTP_XOR_MULT_DOSStub_0a96 {
  strings:
    $key_0a96 = { 5e fe [2] 2a e6 [2] 6d e4 [2] 2a f5 [2] 64 f9 [2] 68 f3 [2] 7f f8 [2] 64 b6 [2] 59 }

  condition:
    any of them
}