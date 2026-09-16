rule TTP_XOR_MULT_DOSStub_8cb9 {
  strings:
    $key_8cb9 = { d8 d1 [2] ac c9 [2] eb cb [2] ac da [2] e2 d6 [2] ee dc [2] f9 d7 [2] e2 99 [2] df }

  condition:
    any of them
}