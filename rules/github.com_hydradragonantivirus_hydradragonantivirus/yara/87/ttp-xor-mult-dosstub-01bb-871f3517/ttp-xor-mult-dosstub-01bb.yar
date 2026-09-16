rule TTP_XOR_MULT_DOSStub_01bb {
  strings:
    $key_01bb = { 55 d3 [2] 21 cb [2] 66 c9 [2] 21 d8 [2] 6f d4 [2] 63 de [2] 74 d5 [2] 6f 9b [2] 52 }

  condition:
    any of them
}