rule TTP_XOR_MULT_DOSStub_b8d1 {
  strings:
    $key_b8d1 = { ec b9 [2] 98 a1 [2] df a3 [2] 98 b2 [2] d6 be [2] da b4 [2] cd bf [2] d6 f1 [2] eb }

  condition:
    any of them
}