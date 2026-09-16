rule TTP_XOR_MULT_DOSStub_6da1 {
  strings:
    $key_6da1 = { 39 c9 [2] 4d d1 [2] 0a d3 [2] 4d c2 [2] 03 ce [2] 0f c4 [2] 18 cf [2] 03 81 [2] 3e }

  condition:
    any of them
}