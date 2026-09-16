rule TTP_XOR_MULT_DOSStub_44bb {
  strings:
    $key_44bb = { 10 d3 [2] 64 cb [2] 23 c9 [2] 64 d8 [2] 2a d4 [2] 26 de [2] 31 d5 [2] 2a 9b [2] 17 }

  condition:
    any of them
}