rule TTP_XOR_MULT_DOSStub_80b1 {
  strings:
    $key_80b1 = { d4 d9 [2] a0 c1 [2] e7 c3 [2] a0 d2 [2] ee de [2] e2 d4 [2] f5 df [2] ee 91 [2] d3 }

  condition:
    any of them
}