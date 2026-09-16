rule TTP_XOR_MULT_DOSStub_5f87 {
  strings:
    $key_5f87 = { 0b ef [2] 7f f7 [2] 38 f5 [2] 7f e4 [2] 31 e8 [2] 3d e2 [2] 2a e9 [2] 31 a7 [2] 0c }

  condition:
    any of them
}