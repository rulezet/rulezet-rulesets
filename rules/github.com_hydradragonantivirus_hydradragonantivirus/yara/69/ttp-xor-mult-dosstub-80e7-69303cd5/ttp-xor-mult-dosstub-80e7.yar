rule TTP_XOR_MULT_DOSStub_80e7 {
  strings:
    $key_80e7 = { d4 8f [2] a0 97 [2] e7 95 [2] a0 84 [2] ee 88 [2] e2 82 [2] f5 89 [2] ee c7 [2] d3 }

  condition:
    any of them
}