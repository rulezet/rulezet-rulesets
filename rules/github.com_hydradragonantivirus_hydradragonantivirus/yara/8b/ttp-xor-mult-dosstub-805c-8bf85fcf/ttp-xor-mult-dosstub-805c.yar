rule TTP_XOR_MULT_DOSStub_805c {
  strings:
    $key_805c = { d4 34 [2] a0 2c [2] e7 2e [2] a0 3f [2] ee 33 [2] e2 39 [2] f5 32 [2] ee 7c [2] d3 }

  condition:
    any of them
}