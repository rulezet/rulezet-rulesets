rule TTP_XOR_MULT_DOSStub_93bb {
  strings:
    $key_93bb = { c7 d3 [2] b3 cb [2] f4 c9 [2] b3 d8 [2] fd d4 [2] f1 de [2] e6 d5 [2] fd 9b [2] c0 }

  condition:
    any of them
}