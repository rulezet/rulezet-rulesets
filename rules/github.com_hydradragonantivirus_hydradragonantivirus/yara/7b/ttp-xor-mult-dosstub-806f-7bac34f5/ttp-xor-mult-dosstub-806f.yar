rule TTP_XOR_MULT_DOSStub_806f {
  strings:
    $key_806f = { d4 07 [2] a0 1f [2] e7 1d [2] a0 0c [2] ee 00 [2] e2 0a [2] f5 01 [2] ee 4f [2] d3 }

  condition:
    any of them
}