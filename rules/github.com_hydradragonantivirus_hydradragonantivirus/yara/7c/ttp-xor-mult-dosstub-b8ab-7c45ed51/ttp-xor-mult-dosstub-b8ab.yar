rule TTP_XOR_MULT_DOSStub_b8ab {
  strings:
    $key_b8ab = { ec c3 [2] 98 db [2] df d9 [2] 98 c8 [2] d6 c4 [2] da ce [2] cd c5 [2] d6 8b [2] eb }

  condition:
    any of them
}