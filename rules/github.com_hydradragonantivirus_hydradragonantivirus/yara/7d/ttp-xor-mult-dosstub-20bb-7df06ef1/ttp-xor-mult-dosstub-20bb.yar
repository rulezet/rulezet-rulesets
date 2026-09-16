rule TTP_XOR_MULT_DOSStub_20bb {
  strings:
    $key_20bb = { 74 d3 [2] 00 cb [2] 47 c9 [2] 00 d8 [2] 4e d4 [2] 42 de [2] 55 d5 [2] 4e 9b [2] 73 }

  condition:
    any of them
}