rule TTP_XOR_MULT_DOSStub_807f {
  strings:
    $key_807f = { d4 17 [2] a0 0f [2] e7 0d [2] a0 1c [2] ee 10 [2] e2 1a [2] f5 11 [2] ee 5f [2] d3 }

  condition:
    any of them
}