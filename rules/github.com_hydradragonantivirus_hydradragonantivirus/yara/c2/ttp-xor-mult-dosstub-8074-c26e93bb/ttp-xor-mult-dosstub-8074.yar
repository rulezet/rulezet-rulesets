rule TTP_XOR_MULT_DOSStub_8074 {
  strings:
    $key_8074 = { d4 1c [2] a0 04 [2] e7 06 [2] a0 17 [2] ee 1b [2] e2 11 [2] f5 1a [2] ee 54 [2] d3 }

  condition:
    any of them
}