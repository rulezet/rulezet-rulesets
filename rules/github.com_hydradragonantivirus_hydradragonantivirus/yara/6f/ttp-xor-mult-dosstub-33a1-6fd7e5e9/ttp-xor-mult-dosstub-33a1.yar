rule TTP_XOR_MULT_DOSStub_33a1 {
  strings:
    $key_33a1 = { 67 c9 [2] 13 d1 [2] 54 d3 [2] 13 c2 [2] 5d ce [2] 51 c4 [2] 46 cf [2] 5d 81 [2] 60 }

  condition:
    any of them
}