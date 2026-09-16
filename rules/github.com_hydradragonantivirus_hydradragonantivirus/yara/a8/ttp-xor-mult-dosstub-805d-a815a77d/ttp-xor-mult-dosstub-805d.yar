rule TTP_XOR_MULT_DOSStub_805d {
  strings:
    $key_805d = { d4 35 [2] a0 2d [2] e7 2f [2] a0 3e [2] ee 32 [2] e2 38 [2] f5 33 [2] ee 7d [2] d3 }

  condition:
    any of them
}