rule TTP_XOR_MULT_DOSStub_800a {
  strings:
    $key_800a = { d4 62 [2] a0 7a [2] e7 78 [2] a0 69 [2] ee 65 [2] e2 6f [2] f5 64 [2] ee 2a [2] d3 }

  condition:
    any of them
}