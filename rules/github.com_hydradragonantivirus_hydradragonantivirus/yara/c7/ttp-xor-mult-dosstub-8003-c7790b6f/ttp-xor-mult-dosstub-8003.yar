rule TTP_XOR_MULT_DOSStub_8003 {
  strings:
    $key_8003 = { d4 6b [2] a0 73 [2] e7 71 [2] a0 60 [2] ee 6c [2] e2 66 [2] f5 6d [2] ee 23 [2] d3 }

  condition:
    any of them
}