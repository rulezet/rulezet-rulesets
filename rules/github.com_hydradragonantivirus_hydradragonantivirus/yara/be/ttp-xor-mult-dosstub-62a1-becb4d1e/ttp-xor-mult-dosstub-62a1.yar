rule TTP_XOR_MULT_DOSStub_62a1 {
  strings:
    $key_62a1 = { 36 c9 [2] 42 d1 [2] 05 d3 [2] 42 c2 [2] 0c ce [2] 00 c4 [2] 17 cf [2] 0c 81 [2] 31 }

  condition:
    any of them
}