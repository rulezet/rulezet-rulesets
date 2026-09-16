rule TTP_XOR_MULT_DOSStub_800d {
  strings:
    $key_800d = { d4 65 [2] a0 7d [2] e7 7f [2] a0 6e [2] ee 62 [2] e2 68 [2] f5 63 [2] ee 2d [2] d3 }

  condition:
    any of them
}