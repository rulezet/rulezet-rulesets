rule TTP_XOR_MULT_DOSStub_8075 {
  strings:
    $key_8075 = { d4 1d [2] a0 05 [2] e7 07 [2] a0 16 [2] ee 1a [2] e2 10 [2] f5 1b [2] ee 55 [2] d3 }

  condition:
    any of them
}