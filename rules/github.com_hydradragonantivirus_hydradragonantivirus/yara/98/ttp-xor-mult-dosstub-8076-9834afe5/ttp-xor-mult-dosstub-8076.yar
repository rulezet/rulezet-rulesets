rule TTP_XOR_MULT_DOSStub_8076 {
  strings:
    $key_8076 = { d4 1e [2] a0 06 [2] e7 04 [2] a0 15 [2] ee 19 [2] e2 13 [2] f5 18 [2] ee 56 [2] d3 }

  condition:
    any of them
}