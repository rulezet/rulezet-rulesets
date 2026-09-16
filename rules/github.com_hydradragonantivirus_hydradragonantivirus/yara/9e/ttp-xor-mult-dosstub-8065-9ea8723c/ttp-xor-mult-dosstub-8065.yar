rule TTP_XOR_MULT_DOSStub_8065 {
  strings:
    $key_8065 = { d4 0d [2] a0 15 [2] e7 17 [2] a0 06 [2] ee 0a [2] e2 00 [2] f5 0b [2] ee 45 [2] d3 }

  condition:
    any of them
}