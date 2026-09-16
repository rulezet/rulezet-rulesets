rule TTP_XOR_MULT_DOSStub_3d81 {
  strings:
    $key_3d81 = { 69 e9 [2] 1d f1 [2] 5a f3 [2] 1d e2 [2] 53 ee [2] 5f e4 [2] 48 ef [2] 53 a1 [2] 6e }

  condition:
    any of them
}