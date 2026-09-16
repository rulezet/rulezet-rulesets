rule TTP_XOR_MULT_DOSStub_8023 {
  strings:
    $key_8023 = { d4 4b [2] a0 53 [2] e7 51 [2] a0 40 [2] ee 4c [2] e2 46 [2] f5 4d [2] ee 03 [2] d3 }

  condition:
    any of them
}