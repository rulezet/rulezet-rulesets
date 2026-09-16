rule TTP_XOR_MULT_DOSStub_55a1 {
  strings:
    $key_55a1 = { 01 c9 [2] 75 d1 [2] 32 d3 [2] 75 c2 [2] 3b ce [2] 37 c4 [2] 20 cf [2] 3b 81 [2] 06 }

  condition:
    any of them
}