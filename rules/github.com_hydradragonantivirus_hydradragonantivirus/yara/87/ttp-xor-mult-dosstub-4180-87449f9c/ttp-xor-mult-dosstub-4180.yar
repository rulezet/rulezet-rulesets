rule TTP_XOR_MULT_DOSStub_4180 {
  strings:
    $key_4180 = { 15 e8 [2] 61 f0 [2] 26 f2 [2] 61 e3 [2] 2f ef [2] 23 e5 [2] 34 ee [2] 2f a0 [2] 12 }

  condition:
    any of them
}