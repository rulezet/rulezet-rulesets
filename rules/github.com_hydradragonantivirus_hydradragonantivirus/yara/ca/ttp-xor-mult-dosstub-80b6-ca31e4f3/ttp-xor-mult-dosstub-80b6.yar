rule TTP_XOR_MULT_DOSStub_80b6 {
  strings:
    $key_80b6 = { d4 de [2] a0 c6 [2] e7 c4 [2] a0 d5 [2] ee d9 [2] e2 d3 [2] f5 d8 [2] ee 96 [2] d3 }

  condition:
    any of them
}