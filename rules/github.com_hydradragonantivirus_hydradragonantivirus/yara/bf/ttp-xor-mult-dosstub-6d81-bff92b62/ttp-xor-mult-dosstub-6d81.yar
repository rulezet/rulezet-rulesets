rule TTP_XOR_MULT_DOSStub_6d81 {
  strings:
    $key_6d81 = { 39 e9 [2] 4d f1 [2] 0a f3 [2] 4d e2 [2] 03 ee [2] 0f e4 [2] 18 ef [2] 03 a1 [2] 3e }

  condition:
    any of them
}