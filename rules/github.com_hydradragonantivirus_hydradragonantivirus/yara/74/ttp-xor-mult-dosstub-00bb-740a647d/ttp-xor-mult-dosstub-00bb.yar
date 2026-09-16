rule TTP_XOR_MULT_DOSStub_00bb {
  strings:
    $key_00bb = { 54 d3 [2] 20 cb [2] 67 c9 [2] 20 d8 [2] 6e d4 [2] 62 de [2] 75 d5 [2] 6e 9b [2] 53 }

  condition:
    any of them
}