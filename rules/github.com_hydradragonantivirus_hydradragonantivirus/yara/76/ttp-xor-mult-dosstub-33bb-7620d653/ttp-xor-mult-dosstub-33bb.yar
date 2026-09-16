rule TTP_XOR_MULT_DOSStub_33bb {
  strings:
    $key_33bb = { 67 d3 [2] 13 cb [2] 54 c9 [2] 13 d8 [2] 5d d4 [2] 51 de [2] 46 d5 [2] 5d 9b [2] 60 }

  condition:
    any of them
}