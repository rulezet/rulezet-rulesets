rule TTP_XOR_MULT_DOSStub_8056 {
  strings:
    $key_8056 = { d4 3e [2] a0 26 [2] e7 24 [2] a0 35 [2] ee 39 [2] e2 33 [2] f5 38 [2] ee 76 [2] d3 }

  condition:
    any of them
}