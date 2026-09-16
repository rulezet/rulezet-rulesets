rule TTP_XOR_MULT_DOSStub_cfa1 {
  strings:
    $key_cfa1 = { 9b c9 [2] ef d1 [2] a8 d3 [2] ef c2 [2] a1 ce [2] ad c4 [2] ba cf [2] a1 81 [2] 9c }

  condition:
    any of them
}