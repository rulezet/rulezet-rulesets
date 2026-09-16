rule TTP_XOR_MULT_DOSStub_cab2 {
  strings:
    $key_cab2 = { 9e da [2] ea c2 [2] ad c0 [2] ea d1 [2] a4 dd [2] a8 d7 [2] bf dc [2] a4 92 [2] 99 }

  condition:
    any of them
}