rule TTP_XOR_MULT_DOSStub_80fb {
  strings:
    $key_80fb = { d4 93 [2] a0 8b [2] e7 89 [2] a0 98 [2] ee 94 [2] e2 9e [2] f5 95 [2] ee db [2] d3 }

  condition:
    any of them
}