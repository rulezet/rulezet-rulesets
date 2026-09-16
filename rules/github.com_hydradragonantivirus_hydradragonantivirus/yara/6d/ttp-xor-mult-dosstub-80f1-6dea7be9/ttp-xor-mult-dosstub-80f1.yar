rule TTP_XOR_MULT_DOSStub_80f1 {
  strings:
    $key_80f1 = { d4 99 [2] a0 81 [2] e7 83 [2] a0 92 [2] ee 9e [2] e2 94 [2] f5 9f [2] ee d1 [2] d3 }

  condition:
    any of them
}