rule TTP_XOR_MULT_DOSStub_27a1 {
  strings:
    $key_27a1 = { 73 c9 [2] 07 d1 [2] 40 d3 [2] 07 c2 [2] 49 ce [2] 45 c4 [2] 52 cf [2] 49 81 [2] 74 }

  condition:
    any of them
}