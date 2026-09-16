rule TTP_XOR_MULT_DOSStub_1a81 {
  strings:
    $key_1a81 = { 4e e9 [2] 3a f1 [2] 7d f3 [2] 3a e2 [2] 74 ee [2] 78 e4 [2] 6f ef [2] 74 a1 [2] 49 }

  condition:
    any of them
}