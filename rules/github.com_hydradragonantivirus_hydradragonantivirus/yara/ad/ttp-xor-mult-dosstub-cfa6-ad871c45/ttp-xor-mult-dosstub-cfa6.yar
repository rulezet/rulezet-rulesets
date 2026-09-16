rule TTP_XOR_MULT_DOSStub_cfa6 {
  strings:
    $key_cfa6 = { 9b ce [2] ef d6 [2] a8 d4 [2] ef c5 [2] a1 c9 [2] ad c3 [2] ba c8 [2] a1 86 [2] 9c }

  condition:
    any of them
}