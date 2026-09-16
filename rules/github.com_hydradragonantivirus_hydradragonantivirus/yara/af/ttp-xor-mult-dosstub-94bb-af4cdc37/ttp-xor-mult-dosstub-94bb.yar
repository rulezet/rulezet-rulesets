rule TTP_XOR_MULT_DOSStub_94bb {
  strings:
    $key_94bb = { c0 d3 [2] b4 cb [2] f3 c9 [2] b4 d8 [2] fa d4 [2] f6 de [2] e1 d5 [2] fa 9b [2] c7 }

  condition:
    any of them
}