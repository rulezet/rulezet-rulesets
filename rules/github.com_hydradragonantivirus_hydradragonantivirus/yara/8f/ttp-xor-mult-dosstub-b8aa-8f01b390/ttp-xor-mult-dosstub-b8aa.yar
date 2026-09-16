rule TTP_XOR_MULT_DOSStub_b8aa {
  strings:
    $key_b8aa = { ec c2 [2] 98 da [2] df d8 [2] 98 c9 [2] d6 c5 [2] da cf [2] cd c4 [2] d6 8a [2] eb }

  condition:
    any of them
}