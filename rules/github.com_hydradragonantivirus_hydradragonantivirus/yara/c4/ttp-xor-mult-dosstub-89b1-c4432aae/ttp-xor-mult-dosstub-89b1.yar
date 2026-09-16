rule TTP_XOR_MULT_DOSStub_89b1 {
  strings:
    $key_89b1 = { dd d9 [2] a9 c1 [2] ee c3 [2] a9 d2 [2] e7 de [2] eb d4 [2] fc df [2] e7 91 [2] da }

  condition:
    any of them
}