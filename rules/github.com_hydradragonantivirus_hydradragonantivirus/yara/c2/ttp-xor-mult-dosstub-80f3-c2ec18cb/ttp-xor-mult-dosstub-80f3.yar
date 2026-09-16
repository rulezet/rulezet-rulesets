rule TTP_XOR_MULT_DOSStub_80f3 {
  strings:
    $key_80f3 = { d4 9b [2] a0 83 [2] e7 81 [2] a0 90 [2] ee 9c [2] e2 96 [2] f5 9d [2] ee d3 [2] d3 }

  condition:
    any of them
}