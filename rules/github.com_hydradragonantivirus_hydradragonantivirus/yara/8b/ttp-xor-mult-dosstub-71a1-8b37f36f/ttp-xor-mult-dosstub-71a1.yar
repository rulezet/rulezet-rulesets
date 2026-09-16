rule TTP_XOR_MULT_DOSStub_71a1 {
  strings:
    $key_71a1 = { 25 c9 [2] 51 d1 [2] 16 d3 [2] 51 c2 [2] 1f ce [2] 13 c4 [2] 04 cf [2] 1f 81 [2] 22 }

  condition:
    any of them
}