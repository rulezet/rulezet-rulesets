rule TTP_XOR_MULT_DOSStub_8c4e {
  strings:
    $key_8c4e = { d8 26 [2] ac 3e [2] eb 3c [2] ac 2d [2] e2 21 [2] ee 2b [2] f9 20 [2] e2 6e [2] df }

  condition:
    any of them
}