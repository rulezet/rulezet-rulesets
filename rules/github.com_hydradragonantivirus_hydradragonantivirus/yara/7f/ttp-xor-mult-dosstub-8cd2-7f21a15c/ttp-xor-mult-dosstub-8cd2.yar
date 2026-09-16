rule TTP_XOR_MULT_DOSStub_8cd2 {
  strings:
    $key_8cd2 = { d8 ba [2] ac a2 [2] eb a0 [2] ac b1 [2] e2 bd [2] ee b7 [2] f9 bc [2] e2 f2 [2] df }

  condition:
    any of them
}