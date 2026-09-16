rule TTP_XOR_MULT_DOSStub_80e9 {
  strings:
    $key_80e9 = { d4 81 [2] a0 99 [2] e7 9b [2] a0 8a [2] ee 86 [2] e2 8c [2] f5 87 [2] ee c9 [2] d3 }

  condition:
    any of them
}