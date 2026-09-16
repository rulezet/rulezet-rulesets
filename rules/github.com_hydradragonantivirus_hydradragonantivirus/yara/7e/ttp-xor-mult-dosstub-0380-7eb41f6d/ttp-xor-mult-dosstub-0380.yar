rule TTP_XOR_MULT_DOSStub_0380 {
  strings:
    $key_0380 = { 57 e8 [2] 23 f0 [2] 64 f2 [2] 23 e3 [2] 6d ef [2] 61 e5 [2] 76 ee [2] 6d a0 [2] 50 }

  condition:
    any of them
}