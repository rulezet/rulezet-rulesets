rule TTP_XOR_MULT_DOSStub_30a1 {
  strings:
    $key_30a1 = { 64 c9 [2] 10 d1 [2] 57 d3 [2] 10 c2 [2] 5e ce [2] 52 c4 [2] 45 cf [2] 5e 81 [2] 63 }

  condition:
    any of them
}