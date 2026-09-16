rule TTP_XOR_MULT_DOSStub_8057 {
  strings:
    $key_8057 = { d4 3f [2] a0 27 [2] e7 25 [2] a0 34 [2] ee 38 [2] e2 32 [2] f5 39 [2] ee 77 [2] d3 }

  condition:
    any of them
}