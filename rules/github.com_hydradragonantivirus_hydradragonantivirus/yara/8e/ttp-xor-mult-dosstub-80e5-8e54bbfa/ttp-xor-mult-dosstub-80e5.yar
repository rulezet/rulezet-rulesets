rule TTP_XOR_MULT_DOSStub_80e5 {
  strings:
    $key_80e5 = { d4 8d [2] a0 95 [2] e7 97 [2] a0 86 [2] ee 8a [2] e2 80 [2] f5 8b [2] ee c5 [2] d3 }

  condition:
    any of them
}