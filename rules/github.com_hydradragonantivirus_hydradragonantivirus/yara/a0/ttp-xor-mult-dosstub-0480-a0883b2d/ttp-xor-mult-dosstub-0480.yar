rule TTP_XOR_MULT_DOSStub_0480 {
  strings:
    $key_0480 = { 50 e8 [2] 24 f0 [2] 63 f2 [2] 24 e3 [2] 6a ef [2] 66 e5 [2] 71 ee [2] 6a a0 [2] 57 }

  condition:
    any of them
}