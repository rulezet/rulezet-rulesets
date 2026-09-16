rule TTP_XOR_MULT_DOSStub_76a1 {
  strings:
    $key_76a1 = { 22 c9 [2] 56 d1 [2] 11 d3 [2] 56 c2 [2] 18 ce [2] 14 c4 [2] 03 cf [2] 18 81 [2] 25 }

  condition:
    any of them
}