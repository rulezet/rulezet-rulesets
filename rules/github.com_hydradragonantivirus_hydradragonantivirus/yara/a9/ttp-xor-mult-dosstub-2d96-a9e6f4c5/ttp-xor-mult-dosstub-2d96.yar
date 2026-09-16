rule TTP_XOR_MULT_DOSStub_2d96 {
  strings:
    $key_2d96 = { 79 fe [2] 0d e6 [2] 4a e4 [2] 0d f5 [2] 43 f9 [2] 4f f3 [2] 58 f8 [2] 43 b6 [2] 7e }

  condition:
    any of them
}