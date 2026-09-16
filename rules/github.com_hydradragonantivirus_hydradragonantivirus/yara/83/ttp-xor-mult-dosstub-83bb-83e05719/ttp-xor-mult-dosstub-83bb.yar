rule TTP_XOR_MULT_DOSStub_83bb {
  strings:
    $key_83bb = { d7 d3 [2] a3 cb [2] e4 c9 [2] a3 d8 [2] ed d4 [2] e1 de [2] f6 d5 [2] ed 9b [2] d0 }

  condition:
    any of them
}