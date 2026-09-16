rule TTP_XOR_MULT_DOSStub_60bb {
  strings:
    $key_60bb = { 34 d3 [2] 40 cb [2] 07 c9 [2] 40 d8 [2] 0e d4 [2] 02 de [2] 15 d5 [2] 0e 9b [2] 33 }

  condition:
    any of them
}