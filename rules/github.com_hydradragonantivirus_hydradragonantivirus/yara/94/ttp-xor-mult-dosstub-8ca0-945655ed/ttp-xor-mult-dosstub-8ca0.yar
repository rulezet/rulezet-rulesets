rule TTP_XOR_MULT_DOSStub_8ca0 {
  strings:
    $key_8ca0 = { d8 c8 [2] ac d0 [2] eb d2 [2] ac c3 [2] e2 cf [2] ee c5 [2] f9 ce [2] e2 80 [2] df }

  condition:
    any of them
}