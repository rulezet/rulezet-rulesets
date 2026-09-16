rule TTP_XOR_MULT_DOSStub_89b4 {
  strings:
    $key_89b4 = { dd dc [2] a9 c4 [2] ee c6 [2] a9 d7 [2] e7 db [2] eb d1 [2] fc da [2] e7 94 [2] da }

  condition:
    any of them
}