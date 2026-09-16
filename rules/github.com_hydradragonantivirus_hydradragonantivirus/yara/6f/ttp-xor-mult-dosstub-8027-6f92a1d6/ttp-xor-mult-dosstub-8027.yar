rule TTP_XOR_MULT_DOSStub_8027 {
  strings:
    $key_8027 = { d4 4f [2] a0 57 [2] e7 55 [2] a0 44 [2] ee 48 [2] e2 42 [2] f5 49 [2] ee 07 [2] d3 }

  condition:
    any of them
}