rule TTP_XOR_MULT_DOSStub_bca1 {
  strings:
    $key_bca1 = { e8 c9 [2] 9c d1 [2] db d3 [2] 9c c2 [2] d2 ce [2] de c4 [2] c9 cf [2] d2 81 [2] ef }

  condition:
    any of them
}