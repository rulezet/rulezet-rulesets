rule TTP_XOR_MULT_DOSStub_b8d9 {
  strings:
    $key_b8d9 = { ec b1 [2] 98 a9 [2] df ab [2] 98 ba [2] d6 b6 [2] da bc [2] cd b7 [2] d6 f9 [2] eb }

  condition:
    any of them
}