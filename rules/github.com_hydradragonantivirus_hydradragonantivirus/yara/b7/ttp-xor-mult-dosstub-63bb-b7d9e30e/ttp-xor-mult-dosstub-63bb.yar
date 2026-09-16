rule TTP_XOR_MULT_DOSStub_63bb {
  strings:
    $key_63bb = { 37 d3 [2] 43 cb [2] 04 c9 [2] 43 d8 [2] 0d d4 [2] 01 de [2] 16 d5 [2] 0d 9b [2] 30 }

  condition:
    any of them
}