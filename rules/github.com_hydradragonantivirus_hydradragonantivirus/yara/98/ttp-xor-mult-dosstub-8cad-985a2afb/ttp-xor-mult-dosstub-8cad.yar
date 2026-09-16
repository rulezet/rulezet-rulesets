rule TTP_XOR_MULT_DOSStub_8cad {
  strings:
    $key_8cad = { d8 c5 [2] ac dd [2] eb df [2] ac ce [2] e2 c2 [2] ee c8 [2] f9 c3 [2] e2 8d [2] df }

  condition:
    any of them
}