rule TTP_XOR_MULT_DOSStub_807b {
  strings:
    $key_807b = { d4 13 [2] a0 0b [2] e7 09 [2] a0 18 [2] ee 14 [2] e2 1e [2] f5 15 [2] ee 5b [2] d3 }

  condition:
    any of them
}