rule TTP_XOR_MULT_DOSStub_803b {
  strings:
    $key_803b = { d4 53 [2] a0 4b [2] e7 49 [2] a0 58 [2] ee 54 [2] e2 5e [2] f5 55 [2] ee 1b [2] d3 }

  condition:
    any of them
}