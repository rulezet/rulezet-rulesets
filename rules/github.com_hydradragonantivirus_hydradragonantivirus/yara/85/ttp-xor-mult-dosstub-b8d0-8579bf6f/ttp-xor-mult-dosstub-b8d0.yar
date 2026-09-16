rule TTP_XOR_MULT_DOSStub_b8d0 {
  strings:
    $key_b8d0 = { ec b8 [2] 98 a0 [2] df a2 [2] 98 b3 [2] d6 bf [2] da b5 [2] cd be [2] d6 f0 [2] eb }

  condition:
    any of them
}