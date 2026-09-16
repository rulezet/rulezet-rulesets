rule TTP_XOR_MULT_DOSStub_b8ad {
  strings:
    $key_b8ad = { ec c5 [2] 98 dd [2] df df [2] 98 ce [2] d6 c2 [2] da c8 [2] cd c3 [2] d6 8d [2] eb }

  condition:
    any of them
}