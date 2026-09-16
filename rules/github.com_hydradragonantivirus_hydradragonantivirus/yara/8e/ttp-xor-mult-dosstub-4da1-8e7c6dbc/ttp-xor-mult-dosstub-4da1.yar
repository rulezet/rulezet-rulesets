rule TTP_XOR_MULT_DOSStub_4da1 {
  strings:
    $key_4da1 = { 19 c9 [2] 6d d1 [2] 2a d3 [2] 6d c2 [2] 23 ce [2] 2f c4 [2] 38 cf [2] 23 81 [2] 1e }

  condition:
    any of them
}