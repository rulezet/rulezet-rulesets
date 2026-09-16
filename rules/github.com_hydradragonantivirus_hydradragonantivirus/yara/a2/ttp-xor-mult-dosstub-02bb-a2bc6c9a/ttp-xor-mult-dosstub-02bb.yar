rule TTP_XOR_MULT_DOSStub_02bb {
  strings:
    $key_02bb = { 56 d3 [2] 22 cb [2] 65 c9 [2] 22 d8 [2] 6c d4 [2] 60 de [2] 77 d5 [2] 6c 9b [2] 51 }

  condition:
    any of them
}