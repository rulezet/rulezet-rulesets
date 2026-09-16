rule TTP_XOR_MULT_DOSStub_7380 {
  strings:
    $key_7380 = { 27 e8 [2] 53 f0 [2] 14 f2 [2] 53 e3 [2] 1d ef [2] 11 e5 [2] 06 ee [2] 1d a0 [2] 20 }

  condition:
    any of them
}