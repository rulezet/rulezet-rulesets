rule TTP_XOR_MULT_DOSStub_0d81 {
  strings:
    $key_0d81 = { 59 e9 [2] 2d f1 [2] 6a f3 [2] 2d e2 [2] 63 ee [2] 6f e4 [2] 78 ef [2] 63 a1 [2] 5e }

  condition:
    any of them
}