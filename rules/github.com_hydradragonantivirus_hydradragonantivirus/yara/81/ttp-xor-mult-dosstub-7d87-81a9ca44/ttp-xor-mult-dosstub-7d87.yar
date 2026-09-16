rule TTP_XOR_MULT_DOSStub_7d87 {
  strings:
    $key_7d87 = { 29 ef [2] 5d f7 [2] 1a f5 [2] 5d e4 [2] 13 e8 [2] 1f e2 [2] 08 e9 [2] 13 a7 [2] 2e }

  condition:
    any of them
}