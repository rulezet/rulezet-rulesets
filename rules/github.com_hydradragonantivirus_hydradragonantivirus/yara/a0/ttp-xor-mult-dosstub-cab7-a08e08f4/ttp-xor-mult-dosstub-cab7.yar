rule TTP_XOR_MULT_DOSStub_cab7 {
  strings:
    $key_cab7 = { 9e df [2] ea c7 [2] ad c5 [2] ea d4 [2] a4 d8 [2] a8 d2 [2] bf d9 [2] a4 97 [2] 99 }

  condition:
    any of them
}