rule TTP_XOR_MULT_DOSStub_2a96 {
  strings:
    $key_2a96 = { 7e fe [2] 0a e6 [2] 4d e4 [2] 0a f5 [2] 44 f9 [2] 48 f3 [2] 5f f8 [2] 44 b6 [2] 79 }

  condition:
    any of them
}