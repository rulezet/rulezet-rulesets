rule TTP_XOR_MULT_DOSStub_75bb {
  strings:
    $key_75bb = { 21 d3 [2] 55 cb [2] 12 c9 [2] 55 d8 [2] 1b d4 [2] 17 de [2] 00 d5 [2] 1b 9b [2] 26 }

  condition:
    any of them
}