rule TTP_XOR_MULT_DOSStub_41a1 {
  strings:
    $key_41a1 = { 15 c9 [2] 61 d1 [2] 26 d3 [2] 61 c2 [2] 2f ce [2] 23 c4 [2] 34 cf [2] 2f 81 [2] 12 }

  condition:
    any of them
}