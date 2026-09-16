rule TTP_XOR_MULT_DOSStub_23a1 {
  strings:
    $key_23a1 = { 77 c9 [2] 03 d1 [2] 44 d3 [2] 03 c2 [2] 4d ce [2] 41 c4 [2] 56 cf [2] 4d 81 [2] 70 }

  condition:
    any of them
}