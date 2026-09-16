rule TTP_XOR_MULT_DOSStub_36bb {
  strings:
    $key_36bb = { 62 d3 [2] 16 cb [2] 51 c9 [2] 16 d8 [2] 58 d4 [2] 54 de [2] 43 d5 [2] 58 9b [2] 65 }

  condition:
    any of them
}