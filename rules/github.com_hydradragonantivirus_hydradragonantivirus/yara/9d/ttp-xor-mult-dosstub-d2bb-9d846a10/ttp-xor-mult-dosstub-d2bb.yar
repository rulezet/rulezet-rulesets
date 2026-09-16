rule TTP_XOR_MULT_DOSStub_d2bb {
  strings:
    $key_d2bb = { 86 d3 [2] f2 cb [2] b5 c9 [2] f2 d8 [2] bc d4 [2] b0 de [2] a7 d5 [2] bc 9b [2] 81 }

  condition:
    any of them
}