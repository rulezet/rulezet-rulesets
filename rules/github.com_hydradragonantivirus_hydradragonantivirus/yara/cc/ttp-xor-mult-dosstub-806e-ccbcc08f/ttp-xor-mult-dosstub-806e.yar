rule TTP_XOR_MULT_DOSStub_806e {
  strings:
    $key_806e = { d4 06 [2] a0 1e [2] e7 1c [2] a0 0d [2] ee 01 [2] e2 0b [2] f5 00 [2] ee 4e [2] d3 }

  condition:
    any of them
}