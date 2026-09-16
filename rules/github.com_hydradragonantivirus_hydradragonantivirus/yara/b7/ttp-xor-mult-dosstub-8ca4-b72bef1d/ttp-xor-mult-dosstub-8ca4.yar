rule TTP_XOR_MULT_DOSStub_8ca4 {
  strings:
    $key_8ca4 = { d8 cc [2] ac d4 [2] eb d6 [2] ac c7 [2] e2 cb [2] ee c1 [2] f9 ca [2] e2 84 [2] df }

  condition:
    any of them
}