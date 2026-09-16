rule TTP_XOR_MULT_DOSStub_80f2 {
  strings:
    $key_80f2 = { d4 9a [2] a0 82 [2] e7 80 [2] a0 91 [2] ee 9d [2] e2 97 [2] f5 9c [2] ee d2 [2] d3 }

  condition:
    any of them
}