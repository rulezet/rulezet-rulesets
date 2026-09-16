rule TTP_XOR_MULT_DOSStub_1a87 {
  strings:
    $key_1a87 = { 4e ef [2] 3a f7 [2] 7d f5 [2] 3a e4 [2] 74 e8 [2] 78 e2 [2] 6f e9 [2] 74 a7 [2] 49 }

  condition:
    any of them
}