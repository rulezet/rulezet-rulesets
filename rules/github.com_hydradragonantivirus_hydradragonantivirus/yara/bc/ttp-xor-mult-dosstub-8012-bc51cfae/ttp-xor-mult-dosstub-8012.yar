rule TTP_XOR_MULT_DOSStub_8012 {
  strings:
    $key_8012 = { d4 7a [2] a0 62 [2] e7 60 [2] a0 71 [2] ee 7d [2] e2 77 [2] f5 7c [2] ee 32 [2] d3 }

  condition:
    any of them
}