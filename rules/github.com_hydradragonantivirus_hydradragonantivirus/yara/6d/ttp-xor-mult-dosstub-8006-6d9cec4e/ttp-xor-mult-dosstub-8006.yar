rule TTP_XOR_MULT_DOSStub_8006 {
  strings:
    $key_8006 = { d4 6e [2] a0 76 [2] e7 74 [2] a0 65 [2] ee 69 [2] e2 63 [2] f5 68 [2] ee 26 [2] d3 }

  condition:
    any of them
}