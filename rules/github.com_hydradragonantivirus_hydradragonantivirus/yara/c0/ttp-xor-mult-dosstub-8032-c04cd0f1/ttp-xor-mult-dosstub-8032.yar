rule TTP_XOR_MULT_DOSStub_8032 {
  strings:
    $key_8032 = { d4 5a [2] a0 42 [2] e7 40 [2] a0 51 [2] ee 5d [2] e2 57 [2] f5 5c [2] ee 12 [2] d3 }

  condition:
    any of them
}