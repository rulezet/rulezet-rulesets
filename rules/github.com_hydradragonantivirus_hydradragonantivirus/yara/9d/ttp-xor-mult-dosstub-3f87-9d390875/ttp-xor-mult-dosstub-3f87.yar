rule TTP_XOR_MULT_DOSStub_3f87 {
  strings:
    $key_3f87 = { 6b ef [2] 1f f7 [2] 58 f5 [2] 1f e4 [2] 51 e8 [2] 5d e2 [2] 4a e9 [2] 51 a7 [2] 6c }

  condition:
    any of them
}