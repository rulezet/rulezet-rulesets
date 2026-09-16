rule TTP_XOR_MULT_DOSStub_3d87 {
  strings:
    $key_3d87 = { 69 ef [2] 1d f7 [2] 5a f5 [2] 1d e4 [2] 53 e8 [2] 5f e2 [2] 48 e9 [2] 53 a7 [2] 6e }

  condition:
    any of them
}