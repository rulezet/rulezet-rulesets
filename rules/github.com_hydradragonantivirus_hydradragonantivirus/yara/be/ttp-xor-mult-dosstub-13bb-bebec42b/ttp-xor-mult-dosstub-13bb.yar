rule TTP_XOR_MULT_DOSStub_13bb {
  strings:
    $key_13bb = { 47 d3 [2] 33 cb [2] 74 c9 [2] 33 d8 [2] 7d d4 [2] 71 de [2] 66 d5 [2] 7d 9b [2] 40 }

  condition:
    any of them
}