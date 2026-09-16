rule TTP_XOR_MULT_DOSStub_4a87 {
  strings:
    $key_4a87 = { 1e ef [2] 6a f7 [2] 2d f5 [2] 6a e4 [2] 24 e8 [2] 28 e2 [2] 3f e9 [2] 24 a7 [2] 19 }

  condition:
    any of them
}