rule TTP_XOR_MULT_DOSStub_8070 {
  strings:
    $key_8070 = { d4 18 [2] a0 00 [2] e7 02 [2] a0 13 [2] ee 1f [2] e2 15 [2] f5 1e [2] ee 50 [2] d3 }

  condition:
    any of them
}