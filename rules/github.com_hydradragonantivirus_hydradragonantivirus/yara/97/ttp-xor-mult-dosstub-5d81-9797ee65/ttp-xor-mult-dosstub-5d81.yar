rule TTP_XOR_MULT_DOSStub_5d81 {
  strings:
    $key_5d81 = { 09 e9 [2] 7d f1 [2] 3a f3 [2] 7d e2 [2] 33 ee [2] 3f e4 [2] 28 ef [2] 33 a1 [2] 0e }

  condition:
    any of them
}