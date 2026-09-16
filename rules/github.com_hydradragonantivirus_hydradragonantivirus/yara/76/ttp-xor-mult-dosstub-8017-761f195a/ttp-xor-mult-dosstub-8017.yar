rule TTP_XOR_MULT_DOSStub_8017 {
  strings:
    $key_8017 = { d4 7f [2] a0 67 [2] e7 65 [2] a0 74 [2] ee 78 [2] e2 72 [2] f5 79 [2] ee 37 [2] d3 }

  condition:
    any of them
}