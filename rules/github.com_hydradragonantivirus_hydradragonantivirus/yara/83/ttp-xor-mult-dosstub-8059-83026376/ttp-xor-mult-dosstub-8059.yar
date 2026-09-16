rule TTP_XOR_MULT_DOSStub_8059 {
  strings:
    $key_8059 = { d4 31 [2] a0 29 [2] e7 2b [2] a0 3a [2] ee 36 [2] e2 3c [2] f5 37 [2] ee 79 [2] d3 }

  condition:
    any of them
}