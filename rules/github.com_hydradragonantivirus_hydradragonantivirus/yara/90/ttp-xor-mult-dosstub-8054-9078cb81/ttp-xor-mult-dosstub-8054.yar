rule TTP_XOR_MULT_DOSStub_8054 {
  strings:
    $key_8054 = { d4 3c [2] a0 24 [2] e7 26 [2] a0 37 [2] ee 3b [2] e2 31 [2] f5 3a [2] ee 74 [2] d3 }

  condition:
    any of them
}