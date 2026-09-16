rule TTP_XOR_MULT_DOSStub_8043 {
  strings:
    $key_8043 = { d4 2b [2] a0 33 [2] e7 31 [2] a0 20 [2] ee 2c [2] e2 26 [2] f5 2d [2] ee 63 [2] d3 }

  condition:
    any of them
}