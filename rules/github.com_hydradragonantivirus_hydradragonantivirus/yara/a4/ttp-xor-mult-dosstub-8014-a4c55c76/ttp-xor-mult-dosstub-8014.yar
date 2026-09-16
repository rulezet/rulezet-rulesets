rule TTP_XOR_MULT_DOSStub_8014 {
  strings:
    $key_8014 = { d4 7c [2] a0 64 [2] e7 66 [2] a0 77 [2] ee 7b [2] e2 71 [2] f5 7a [2] ee 34 [2] d3 }

  condition:
    any of them
}