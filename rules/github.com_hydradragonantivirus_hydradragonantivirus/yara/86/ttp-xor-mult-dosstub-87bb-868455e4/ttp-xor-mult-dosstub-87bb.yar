rule TTP_XOR_MULT_DOSStub_87bb {
  strings:
    $key_87bb = { d3 d3 [2] a7 cb [2] e0 c9 [2] a7 d8 [2] e9 d4 [2] e5 de [2] f2 d5 [2] e9 9b [2] d4 }

  condition:
    any of them
}