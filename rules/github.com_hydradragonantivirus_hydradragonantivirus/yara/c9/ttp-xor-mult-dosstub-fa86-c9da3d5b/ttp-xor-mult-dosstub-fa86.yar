rule TTP_XOR_MULT_DOSStub_fa86 {
  strings:
    $key_fa86 = { ae ee [2] da f6 [2] 9d f4 [2] da e5 [2] 94 e9 [2] 98 e3 [2] 8f e8 [2] 94 a6 [2] a9 }

  condition:
    any of them
}