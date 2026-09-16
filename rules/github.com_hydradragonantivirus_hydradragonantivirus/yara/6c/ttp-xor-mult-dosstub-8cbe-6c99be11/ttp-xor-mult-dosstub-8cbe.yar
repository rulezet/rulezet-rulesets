rule TTP_XOR_MULT_DOSStub_8cbe {
  strings:
    $key_8cbe = { d8 d6 [2] ac ce [2] eb cc [2] ac dd [2] e2 d1 [2] ee db [2] f9 d0 [2] e2 9e [2] df }

  condition:
    any of them
}