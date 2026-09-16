rule TTP_XOR_MULT_DOSStub_02a1 {
  strings:
    $key_02a1 = { 56 c9 [2] 22 d1 [2] 65 d3 [2] 22 c2 [2] 6c ce [2] 60 c4 [2] 77 cf [2] 6c 81 [2] 51 }

  condition:
    any of them
}