rule TTP_XOR_MULT_DOSStub_80e4 {
  strings:
    $key_80e4 = { d4 8c [2] a0 94 [2] e7 96 [2] a0 87 [2] ee 8b [2] e2 81 [2] f5 8a [2] ee c4 [2] d3 }

  condition:
    any of them
}