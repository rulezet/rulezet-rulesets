rule TTP_XOR_MULT_DOSStub_804c {
  strings:
    $key_804c = { d4 24 [2] a0 3c [2] e7 3e [2] a0 2f [2] ee 23 [2] e2 29 [2] f5 22 [2] ee 6c [2] d3 }

  condition:
    any of them
}