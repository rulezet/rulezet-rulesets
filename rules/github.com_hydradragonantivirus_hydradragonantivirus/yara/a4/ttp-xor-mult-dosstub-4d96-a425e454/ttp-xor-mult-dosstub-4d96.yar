rule TTP_XOR_MULT_DOSStub_4d96 {
  strings:
    $key_4d96 = { 19 fe [2] 6d e6 [2] 2a e4 [2] 6d f5 [2] 23 f9 [2] 2f f3 [2] 38 f8 [2] 23 b6 [2] 1e }

  condition:
    any of them
}