rule TTP_XOR_MULT_DOSStub_89b7 {
  strings:
    $key_89b7 = { dd df [2] a9 c7 [2] ee c5 [2] a9 d4 [2] e7 d8 [2] eb d2 [2] fc d9 [2] e7 97 [2] da }

  condition:
    any of them
}