rule TTP_XOR_MULT_DOSStub_89b0 {
  strings:
    $key_89b0 = { dd d8 [2] a9 c0 [2] ee c2 [2] a9 d3 [2] e7 df [2] eb d5 [2] fc de [2] e7 90 [2] da }

  condition:
    any of them
}