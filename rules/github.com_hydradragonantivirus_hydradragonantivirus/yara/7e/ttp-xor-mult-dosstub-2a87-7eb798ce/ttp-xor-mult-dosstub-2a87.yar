rule TTP_XOR_MULT_DOSStub_2a87 {
  strings:
    $key_2a87 = { 7e ef [2] 0a f7 [2] 4d f5 [2] 0a e4 [2] 44 e8 [2] 48 e2 [2] 5f e9 [2] 44 a7 [2] 79 }

  condition:
    any of them
}