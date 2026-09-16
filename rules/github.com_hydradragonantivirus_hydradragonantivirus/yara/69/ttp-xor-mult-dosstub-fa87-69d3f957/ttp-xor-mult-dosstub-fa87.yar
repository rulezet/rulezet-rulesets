rule TTP_XOR_MULT_DOSStub_fa87 {
  strings:
    $key_fa87 = { ae ef [2] da f7 [2] 9d f5 [2] da e4 [2] 94 e8 [2] 98 e2 [2] 8f e9 [2] 94 a7 [2] a9 }

  condition:
    any of them
}