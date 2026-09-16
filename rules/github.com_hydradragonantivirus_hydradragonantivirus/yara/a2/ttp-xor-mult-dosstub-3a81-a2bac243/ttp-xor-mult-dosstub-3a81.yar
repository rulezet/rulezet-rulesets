rule TTP_XOR_MULT_DOSStub_3a81 {
  strings:
    $key_3a81 = { 6e e9 [2] 1a f1 [2] 5d f3 [2] 1a e2 [2] 54 ee [2] 58 e4 [2] 4f ef [2] 54 a1 [2] 69 }

  condition:
    any of them
}