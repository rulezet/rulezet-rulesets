rule TTP_XOR_MULT_DOSStub_7a81 {
  strings:
    $key_7a81 = { 2e e9 [2] 5a f1 [2] 1d f3 [2] 5a e2 [2] 14 ee [2] 18 e4 [2] 0f ef [2] 14 a1 [2] 29 }

  condition:
    any of them
}