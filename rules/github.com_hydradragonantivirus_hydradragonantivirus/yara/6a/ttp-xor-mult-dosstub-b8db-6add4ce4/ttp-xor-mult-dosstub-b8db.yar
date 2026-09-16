rule TTP_XOR_MULT_DOSStub_b8db {
  strings:
    $key_b8db = { ec b3 [2] 98 ab [2] df a9 [2] 98 b8 [2] d6 b4 [2] da be [2] cd b5 [2] d6 fb [2] eb }

  condition:
    any of them
}