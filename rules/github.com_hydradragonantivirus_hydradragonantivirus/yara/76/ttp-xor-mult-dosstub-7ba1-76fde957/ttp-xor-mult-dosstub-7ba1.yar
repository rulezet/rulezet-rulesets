rule TTP_XOR_MULT_DOSStub_7ba1 {
  strings:
    $key_7ba1 = { 2f c9 [2] 5b d1 [2] 1c d3 [2] 5b c2 [2] 15 ce [2] 19 c4 [2] 0e cf [2] 15 81 [2] 28 }

  condition:
    any of them
}