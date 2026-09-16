rule TTP_XOR_MULT_DOSStub_77bb {
  strings:
    $key_77bb = { 23 d3 [2] 57 cb [2] 10 c9 [2] 57 d8 [2] 19 d4 [2] 15 de [2] 02 d5 [2] 19 9b [2] 24 }

  condition:
    any of them
}