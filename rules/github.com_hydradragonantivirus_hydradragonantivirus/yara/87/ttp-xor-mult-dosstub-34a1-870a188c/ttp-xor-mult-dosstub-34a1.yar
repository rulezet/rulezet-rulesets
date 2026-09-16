rule TTP_XOR_MULT_DOSStub_34a1 {
  strings:
    $key_34a1 = { 60 c9 [2] 14 d1 [2] 53 d3 [2] 14 c2 [2] 5a ce [2] 56 c4 [2] 41 cf [2] 5a 81 [2] 67 }

  condition:
    any of them
}