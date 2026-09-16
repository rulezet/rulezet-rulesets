rule TTP_XOR_MULT_DOSStub_10bb {
  strings:
    $key_10bb = { 44 d3 [2] 30 cb [2] 77 c9 [2] 30 d8 [2] 7e d4 [2] 72 de [2] 65 d5 [2] 7e 9b [2] 43 }

  condition:
    any of them
}