rule TTP_XOR_MULT_DOSStub_5480 {
  strings:
    $key_5480 = { 00 e8 [2] 74 f0 [2] 33 f2 [2] 74 e3 [2] 3a ef [2] 36 e5 [2] 21 ee [2] 3a a0 [2] 07 }

  condition:
    any of them
}