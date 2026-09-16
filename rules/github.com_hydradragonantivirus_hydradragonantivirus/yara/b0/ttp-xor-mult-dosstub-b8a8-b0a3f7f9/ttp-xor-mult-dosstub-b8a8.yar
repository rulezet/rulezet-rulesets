rule TTP_XOR_MULT_DOSStub_b8a8 {
  strings:
    $key_b8a8 = { ec c0 [2] 98 d8 [2] df da [2] 98 cb [2] d6 c7 [2] da cd [2] cd c6 [2] d6 88 [2] eb }

  condition:
    any of them
}