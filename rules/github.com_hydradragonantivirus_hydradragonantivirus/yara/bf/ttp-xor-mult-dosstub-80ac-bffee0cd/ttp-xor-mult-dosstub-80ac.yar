rule TTP_XOR_MULT_DOSStub_80ac {
  strings:
    $key_80ac = { d4 c4 [2] a0 dc [2] e7 de [2] a0 cf [2] ee c3 [2] e2 c9 [2] f5 c2 [2] ee 8c [2] d3 }

  condition:
    any of them
}