rule TTP_XOR_MULT_DOSStub_b8d6 {
  strings:
    $key_b8d6 = { ec be [2] 98 a6 [2] df a4 [2] 98 b5 [2] d6 b9 [2] da b3 [2] cd b8 [2] d6 f6 [2] eb }

  condition:
    any of them
}