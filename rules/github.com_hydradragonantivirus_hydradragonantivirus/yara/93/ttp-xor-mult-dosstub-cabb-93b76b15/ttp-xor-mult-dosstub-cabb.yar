rule TTP_XOR_MULT_DOSStub_cabb {
  strings:
    $key_cabb = { 9e d3 [2] ea cb [2] ad c9 [2] ea d8 [2] a4 d4 [2] a8 de [2] bf d5 [2] a4 9b [2] 99 }

  condition:
    any of them
}