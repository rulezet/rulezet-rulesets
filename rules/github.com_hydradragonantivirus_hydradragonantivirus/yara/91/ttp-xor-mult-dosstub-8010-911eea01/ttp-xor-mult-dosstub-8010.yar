rule TTP_XOR_MULT_DOSStub_8010 {
  strings:
    $key_8010 = { d4 78 [2] a0 60 [2] e7 62 [2] a0 73 [2] ee 7f [2] e2 75 [2] f5 7e [2] ee 30 [2] d3 }

  condition:
    any of them
}