rule TTP_XOR_MULT_DOSStub_80e2 {
  strings:
    $key_80e2 = { d4 8a [2] a0 92 [2] e7 90 [2] a0 81 [2] ee 8d [2] e2 87 [2] f5 8c [2] ee c2 [2] d3 }

  condition:
    any of them
}