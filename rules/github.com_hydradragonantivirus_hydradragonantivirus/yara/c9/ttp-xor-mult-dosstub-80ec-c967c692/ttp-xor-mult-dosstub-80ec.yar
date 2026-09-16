rule TTP_XOR_MULT_DOSStub_80ec {
  strings:
    $key_80ec = { d4 84 [2] a0 9c [2] e7 9e [2] a0 8f [2] ee 83 [2] e2 89 [2] f5 82 [2] ee cc [2] d3 }

  condition:
    any of them
}