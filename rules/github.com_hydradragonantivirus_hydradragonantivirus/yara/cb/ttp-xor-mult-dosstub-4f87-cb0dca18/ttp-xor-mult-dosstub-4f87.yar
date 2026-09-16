rule TTP_XOR_MULT_DOSStub_4f87 {
  strings:
    $key_4f87 = { 1b ef [2] 6f f7 [2] 28 f5 [2] 6f e4 [2] 21 e8 [2] 2d e2 [2] 3a e9 [2] 21 a7 [2] 1c }

  condition:
    any of them
}