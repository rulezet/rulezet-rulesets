rule TTP_XOR_MULT_DOSStub_b887 {
  strings:
    $key_b887 = { ec ef [2] 98 f7 [2] df f5 [2] 98 e4 [2] d6 e8 [2] da e2 [2] cd e9 [2] d6 a7 [2] eb }

  condition:
    any of them
}