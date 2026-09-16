rule TTP_XOR_MULT_DOSStub_8025 {
  strings:
    $key_8025 = { d4 4d [2] a0 55 [2] e7 57 [2] a0 46 [2] ee 4a [2] e2 40 [2] f5 4b [2] ee 05 [2] d3 }

  condition:
    any of them
}