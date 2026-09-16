rule TTP_XOR_MULT_DOSStub_b8d2 {
  strings:
    $key_b8d2 = { ec ba [2] 98 a2 [2] df a0 [2] 98 b1 [2] d6 bd [2] da b7 [2] cd bc [2] d6 f2 [2] eb }

  condition:
    any of them
}