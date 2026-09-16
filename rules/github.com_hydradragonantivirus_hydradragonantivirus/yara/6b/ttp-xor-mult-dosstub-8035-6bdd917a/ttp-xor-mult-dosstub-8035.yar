rule TTP_XOR_MULT_DOSStub_8035 {
  strings:
    $key_8035 = { d4 5d [2] a0 45 [2] e7 47 [2] a0 56 [2] ee 5a [2] e2 50 [2] f5 5b [2] ee 15 [2] d3 }

  condition:
    any of them
}