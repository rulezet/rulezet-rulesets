rule TTP_XOR_MULT_DOSStub_1180 {
  strings:
    $key_1180 = { 45 e8 [2] 31 f0 [2] 76 f2 [2] 31 e3 [2] 7f ef [2] 73 e5 [2] 64 ee [2] 7f a0 [2] 42 }

  condition:
    any of them
}