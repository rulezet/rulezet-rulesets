rule TTP_XOR_MULT_DOSStub_fa81 {
  strings:
    $key_fa81 = { ae e9 [2] da f1 [2] 9d f3 [2] da e2 [2] 94 ee [2] 98 e4 [2] 8f ef [2] 94 a1 [2] a9 }

  condition:
    any of them
}