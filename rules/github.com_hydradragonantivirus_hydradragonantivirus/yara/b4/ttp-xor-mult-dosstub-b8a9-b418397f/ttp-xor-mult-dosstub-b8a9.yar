rule TTP_XOR_MULT_DOSStub_b8a9 {
  strings:
    $key_b8a9 = { ec c1 [2] 98 d9 [2] df db [2] 98 ca [2] d6 c6 [2] da cc [2] cd c7 [2] d6 89 [2] eb }

  condition:
    any of them
}