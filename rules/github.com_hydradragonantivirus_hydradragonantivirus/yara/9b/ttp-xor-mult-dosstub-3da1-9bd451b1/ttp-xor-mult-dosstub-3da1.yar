rule TTP_XOR_MULT_DOSStub_3da1 {
  strings:
    $key_3da1 = { 69 c9 [2] 1d d1 [2] 5a d3 [2] 1d c2 [2] 53 ce [2] 5f c4 [2] 48 cf [2] 53 81 [2] 6e }

  condition:
    any of them
}