rule TTP_XOR_MULT_DOSStub_22bb {
  strings:
    $key_22bb = { 76 d3 [2] 02 cb [2] 45 c9 [2] 02 d8 [2] 4c d4 [2] 40 de [2] 57 d5 [2] 4c 9b [2] 71 }

  condition:
    any of them
}