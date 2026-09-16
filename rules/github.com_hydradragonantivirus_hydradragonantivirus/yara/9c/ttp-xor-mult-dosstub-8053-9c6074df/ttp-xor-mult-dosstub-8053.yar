rule TTP_XOR_MULT_DOSStub_8053 {
  strings:
    $key_8053 = { d4 3b [2] a0 23 [2] e7 21 [2] a0 30 [2] ee 3c [2] e2 36 [2] f5 3d [2] ee 73 [2] d3 }

  condition:
    any of them
}