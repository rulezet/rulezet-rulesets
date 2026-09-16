rule TTP_XOR_MULT_DOSStub_80f7 {
  strings:
    $key_80f7 = { d4 9f [2] a0 87 [2] e7 85 [2] a0 94 [2] ee 98 [2] e2 92 [2] f5 99 [2] ee d7 [2] d3 }

  condition:
    any of them
}