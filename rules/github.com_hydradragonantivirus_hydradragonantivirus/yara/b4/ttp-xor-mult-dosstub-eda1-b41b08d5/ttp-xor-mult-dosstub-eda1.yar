rule TTP_XOR_MULT_DOSStub_eda1 {
  strings:
    $key_eda1 = { b9 c9 [2] cd d1 [2] 8a d3 [2] cd c2 [2] 83 ce [2] 8f c4 [2] 98 cf [2] 83 81 [2] be }

  condition:
    any of them
}