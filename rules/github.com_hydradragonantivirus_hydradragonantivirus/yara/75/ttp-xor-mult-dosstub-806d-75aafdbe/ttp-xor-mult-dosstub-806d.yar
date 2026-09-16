rule TTP_XOR_MULT_DOSStub_806d {
  strings:
    $key_806d = { d4 05 [2] a0 1d [2] e7 1f [2] a0 0e [2] ee 02 [2] e2 08 [2] f5 03 [2] ee 4d [2] d3 }

  condition:
    any of them
}