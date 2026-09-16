rule TTP_XOR_MULT_DOSStub_804a {
  strings:
    $key_804a = { d4 22 [2] a0 3a [2] e7 38 [2] a0 29 [2] ee 25 [2] e2 2f [2] f5 24 [2] ee 6a [2] d3 }

  condition:
    any of them
}