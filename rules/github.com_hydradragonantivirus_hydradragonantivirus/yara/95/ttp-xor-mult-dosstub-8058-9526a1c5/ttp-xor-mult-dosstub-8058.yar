rule TTP_XOR_MULT_DOSStub_8058 {
  strings:
    $key_8058 = { d4 30 [2] a0 28 [2] e7 2a [2] a0 3b [2] ee 37 [2] e2 3d [2] f5 36 [2] ee 78 [2] d3 }

  condition:
    any of them
}