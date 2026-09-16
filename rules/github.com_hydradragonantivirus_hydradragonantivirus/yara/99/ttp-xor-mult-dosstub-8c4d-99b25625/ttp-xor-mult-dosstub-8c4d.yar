rule TTP_XOR_MULT_DOSStub_8c4d {
  strings:
    $key_8c4d = { d8 25 [2] ac 3d [2] eb 3f [2] ac 2e [2] e2 22 [2] ee 28 [2] f9 23 [2] e2 6d [2] df }

  condition:
    any of them
}