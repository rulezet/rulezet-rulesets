rule TTP_XOR_MULT_DOSStub_8c2d {
  strings:
    $key_8c2d = { d8 45 [2] ac 5d [2] eb 5f [2] ac 4e [2] e2 42 [2] ee 48 [2] f9 43 [2] e2 0d [2] df }

  condition:
    any of them
}