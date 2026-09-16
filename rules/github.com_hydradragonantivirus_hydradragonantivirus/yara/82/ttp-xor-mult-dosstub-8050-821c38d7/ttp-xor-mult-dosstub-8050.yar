rule TTP_XOR_MULT_DOSStub_8050 {
  strings:
    $key_8050 = { d4 38 [2] a0 20 [2] e7 22 [2] a0 33 [2] ee 3f [2] e2 35 [2] f5 3e [2] ee 70 [2] d3 }

  condition:
    any of them
}