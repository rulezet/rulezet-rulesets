rule TTP_XOR_MULT_DOSStub_caa1 {
  strings:
    $key_caa1 = { 9e c9 [2] ea d1 [2] ad d3 [2] ea c2 [2] a4 ce [2] a8 c4 [2] bf cf [2] a4 81 [2] 99 }

  condition:
    any of them
}