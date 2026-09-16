rule TTP_XOR_MULT_DOSStub_8029 {
  strings:
    $key_8029 = { d4 41 [2] a0 59 [2] e7 5b [2] a0 4a [2] ee 46 [2] e2 4c [2] f5 47 [2] ee 09 [2] d3 }

  condition:
    any of them
}