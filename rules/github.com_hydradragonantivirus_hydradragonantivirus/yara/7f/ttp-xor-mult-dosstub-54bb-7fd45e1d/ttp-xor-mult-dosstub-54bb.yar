rule TTP_XOR_MULT_DOSStub_54bb {
  strings:
    $key_54bb = { 00 d3 [2] 74 cb [2] 33 c9 [2] 74 d8 [2] 3a d4 [2] 36 de [2] 21 d5 [2] 3a 9b [2] 07 }

  condition:
    any of them
}