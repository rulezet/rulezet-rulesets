rule TTP_XOR_MULT_DOSStub_8034 {
  strings:
    $key_8034 = { d4 5c [2] a0 44 [2] e7 46 [2] a0 57 [2] ee 5b [2] e2 51 [2] f5 5a [2] ee 14 [2] d3 }

  condition:
    any of them
}