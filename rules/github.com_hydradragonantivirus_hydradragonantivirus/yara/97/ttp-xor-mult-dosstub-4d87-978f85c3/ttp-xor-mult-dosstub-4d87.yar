rule TTP_XOR_MULT_DOSStub_4d87 {
  strings:
    $key_4d87 = { 19 ef [2] 6d f7 [2] 2a f5 [2] 6d e4 [2] 23 e8 [2] 2f e2 [2] 38 e9 [2] 23 a7 [2] 1e }

  condition:
    any of them
}