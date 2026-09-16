rule TTP_XOR_MULT_DOSStub_80f5 {
  strings:
    $key_80f5 = { d4 9d [2] a0 85 [2] e7 87 [2] a0 96 [2] ee 9a [2] e2 90 [2] f5 9b [2] ee d5 [2] d3 }

  condition:
    any of them
}