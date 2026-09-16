rule TTP_XOR_MULT_DOSStub_8022 {
  strings:
    $key_8022 = { d4 4a [2] a0 52 [2] e7 50 [2] a0 41 [2] ee 4d [2] e2 47 [2] f5 4c [2] ee 02 [2] d3 }

  condition:
    any of them
}