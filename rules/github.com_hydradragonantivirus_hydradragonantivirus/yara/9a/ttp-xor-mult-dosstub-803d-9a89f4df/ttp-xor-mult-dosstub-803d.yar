rule TTP_XOR_MULT_DOSStub_803d {
  strings:
    $key_803d = { d4 55 [2] a0 4d [2] e7 4f [2] a0 5e [2] ee 52 [2] e2 58 [2] f5 53 [2] ee 1d [2] d3 }

  condition:
    any of them
}