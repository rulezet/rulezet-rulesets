rule TTP_XOR_MULT_DOSStub_1d87 {
  strings:
    $key_1d87 = { 49 ef [2] 3d f7 [2] 7a f5 [2] 3d e4 [2] 73 e8 [2] 7f e2 [2] 68 e9 [2] 73 a7 [2] 4e }

  condition:
    any of them
}