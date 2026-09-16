rule TTP_XOR_MULT_DOSStub_b8a7 {
  strings:
    $key_b8a7 = { ec cf [2] 98 d7 [2] df d5 [2] 98 c4 [2] d6 c8 [2] da c2 [2] cd c9 [2] d6 87 [2] eb }

  condition:
    any of them
}