rule TTP_XOR_MULT_DOSStub_eda7 {
  strings:
    $key_eda7 = { b9 cf [2] cd d7 [2] 8a d5 [2] cd c4 [2] 83 c8 [2] 8f c2 [2] 98 c9 [2] 83 87 [2] be }

  condition:
    any of them
}