rule TTP_XOR_MULT_DOSStub_e280 {
  strings:
    $key_e280 = { b6 e8 [2] c2 f0 [2] 85 f2 [2] c2 e3 [2] 8c ef [2] 80 e5 [2] 97 ee [2] 8c a0 [2] b1 }

  condition:
    any of them
}