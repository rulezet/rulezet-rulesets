rule TTP_XOR_MULT_DOSStub_67bb {
  strings:
    $key_67bb = { 33 d3 [2] 47 cb [2] 00 c9 [2] 47 d8 [2] 09 d4 [2] 05 de [2] 12 d5 [2] 09 9b [2] 34 }

  condition:
    any of them
}