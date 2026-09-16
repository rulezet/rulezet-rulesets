rule TTP_XOR_MULT_DOSStub_807c {
  strings:
    $key_807c = { d4 14 [2] a0 0c [2] e7 0e [2] a0 1f [2] ee 13 [2] e2 19 [2] f5 12 [2] ee 5c [2] d3 }

  condition:
    any of them
}