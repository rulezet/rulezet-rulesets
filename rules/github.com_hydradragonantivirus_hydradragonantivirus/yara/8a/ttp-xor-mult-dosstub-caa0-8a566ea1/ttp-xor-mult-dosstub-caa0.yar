rule TTP_XOR_MULT_DOSStub_caa0 {
  strings:
    $key_caa0 = { 9e c8 [2] ea d0 [2] ad d2 [2] ea c3 [2] a4 cf [2] a8 c5 [2] bf ce [2] a4 80 [2] 99 }

  condition:
    any of them
}