rule TTP_XOR_MULT_DOSStub_66bb {
  strings:
    $key_66bb = { 32 d3 [2] 46 cb [2] 01 c9 [2] 46 d8 [2] 08 d4 [2] 04 de [2] 13 d5 [2] 08 9b [2] 35 }

  condition:
    any of them
}