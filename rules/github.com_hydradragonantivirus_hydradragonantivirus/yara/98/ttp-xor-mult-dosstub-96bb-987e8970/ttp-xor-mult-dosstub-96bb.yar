rule TTP_XOR_MULT_DOSStub_96bb {
  strings:
    $key_96bb = { c2 d3 [2] b6 cb [2] f1 c9 [2] b6 d8 [2] f8 d4 [2] f4 de [2] e3 d5 [2] f8 9b [2] c5 }

  condition:
    any of them
}