rule TTP_XOR_MULT_DOSStub_6a81 {
  strings:
    $key_6a81 = { 3e e9 [2] 4a f1 [2] 0d f3 [2] 4a e2 [2] 04 ee [2] 08 e4 [2] 1f ef [2] 04 a1 [2] 39 }

  condition:
    any of them
}