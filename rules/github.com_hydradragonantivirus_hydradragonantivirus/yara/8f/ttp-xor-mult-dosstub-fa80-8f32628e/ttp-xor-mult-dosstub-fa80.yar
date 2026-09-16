rule TTP_XOR_MULT_DOSStub_fa80 {
  strings:
    $key_fa80 = { ae e8 [2] da f0 [2] 9d f2 [2] da e3 [2] 94 ef [2] 98 e5 [2] 8f ee [2] 94 a0 [2] a9 }

  condition:
    any of them
}