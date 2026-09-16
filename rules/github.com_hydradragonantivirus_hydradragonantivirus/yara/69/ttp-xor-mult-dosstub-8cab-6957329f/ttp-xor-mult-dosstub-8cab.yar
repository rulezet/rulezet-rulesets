rule TTP_XOR_MULT_DOSStub_8cab {
  strings:
    $key_8cab = { d8 c3 [2] ac db [2] eb d9 [2] ac c8 [2] e2 c4 [2] ee ce [2] f9 c5 [2] e2 8b [2] df }

  condition:
    any of them
}