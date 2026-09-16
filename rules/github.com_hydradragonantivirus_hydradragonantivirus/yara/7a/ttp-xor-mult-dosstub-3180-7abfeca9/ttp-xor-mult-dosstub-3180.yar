rule TTP_XOR_MULT_DOSStub_3180 {
  strings:
    $key_3180 = { 65 e8 [2] 11 f0 [2] 56 f2 [2] 11 e3 [2] 5f ef [2] 53 e5 [2] 44 ee [2] 5f a0 [2] 62 }

  condition:
    any of them
}