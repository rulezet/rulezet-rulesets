rule TTP_XOR_MULT_DOSStub_805f {
  strings:
    $key_805f = { d4 37 [2] a0 2f [2] e7 2d [2] a0 3c [2] ee 30 [2] e2 3a [2] f5 31 [2] ee 7f [2] d3 }

  condition:
    any of them
}