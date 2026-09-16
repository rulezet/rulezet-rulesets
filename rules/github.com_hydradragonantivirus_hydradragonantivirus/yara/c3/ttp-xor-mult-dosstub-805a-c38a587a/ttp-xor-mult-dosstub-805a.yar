rule TTP_XOR_MULT_DOSStub_805a {
  strings:
    $key_805a = { d4 32 [2] a0 2a [2] e7 28 [2] a0 39 [2] ee 35 [2] e2 3f [2] f5 34 [2] ee 7a [2] d3 }

  condition:
    any of them
}