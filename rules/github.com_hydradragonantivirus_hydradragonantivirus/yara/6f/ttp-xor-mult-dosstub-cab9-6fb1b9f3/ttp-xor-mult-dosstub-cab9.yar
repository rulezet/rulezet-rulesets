rule TTP_XOR_MULT_DOSStub_cab9 {
  strings:
    $key_cab9 = { 9e d1 [2] ea c9 [2] ad cb [2] ea da [2] a4 d6 [2] a8 dc [2] bf d7 [2] a4 99 [2] 99 }

  condition:
    any of them
}