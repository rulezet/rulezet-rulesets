rule TTP_XOR_MULT_DOSStub_80bb {
  strings:
    $key_80bb = { d4 d3 [2] a0 cb [2] e7 c9 [2] a0 d8 [2] ee d4 [2] e2 de [2] f5 d5 [2] ee 9b [2] d3 }

  condition:
    any of them
}