rule TTP_XOR_MULT_DOSStub_802a {
  strings:
    $key_802a = { d4 42 [2] a0 5a [2] e7 58 [2] a0 49 [2] ee 45 [2] e2 4f [2] f5 44 [2] ee 0a [2] d3 }

  condition:
    any of them
}