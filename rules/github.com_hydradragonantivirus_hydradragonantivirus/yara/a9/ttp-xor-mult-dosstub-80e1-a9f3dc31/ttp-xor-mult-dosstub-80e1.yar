rule TTP_XOR_MULT_DOSStub_80e1 {
  strings:
    $key_80e1 = { d4 89 [2] a0 91 [2] e7 93 [2] a0 82 [2] ee 8e [2] e2 84 [2] f5 8f [2] ee c1 [2] d3 }

  condition:
    any of them
}