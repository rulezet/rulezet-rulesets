rule TTP_XOR_MULT_DOSStub_07a1 {
  strings:
    $key_07a1 = { 53 c9 [2] 27 d1 [2] 60 d3 [2] 27 c2 [2] 69 ce [2] 65 c4 [2] 72 cf [2] 69 81 [2] 54 }

  condition:
    any of them
}