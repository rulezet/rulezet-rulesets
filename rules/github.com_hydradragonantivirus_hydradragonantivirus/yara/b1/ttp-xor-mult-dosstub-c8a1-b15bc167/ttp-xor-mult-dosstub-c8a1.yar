rule TTP_XOR_MULT_DOSStub_c8a1 {
  strings:
    $key_c8a1 = { 9c c9 [2] e8 d1 [2] af d3 [2] e8 c2 [2] a6 ce [2] aa c4 [2] bd cf [2] a6 81 [2] 9b }

  condition:
    any of them
}