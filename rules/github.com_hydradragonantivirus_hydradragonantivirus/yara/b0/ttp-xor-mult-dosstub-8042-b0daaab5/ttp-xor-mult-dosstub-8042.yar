rule TTP_XOR_MULT_DOSStub_8042 {
  strings:
    $key_8042 = { d4 2a [2] a0 32 [2] e7 30 [2] a0 21 [2] ee 2d [2] e2 27 [2] f5 2c [2] ee 62 [2] d3 }

  condition:
    any of them
}