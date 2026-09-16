rule TTP_XOR_MULT_DOSStub_8015 {
  strings:
    $key_8015 = { d4 7d [2] a0 65 [2] e7 67 [2] a0 76 [2] ee 7a [2] e2 70 [2] f5 7b [2] ee 35 [2] d3 }

  condition:
    any of them
}