rule TTP_XOR_MULT_DOSStub_8c7d {
  strings:
    $key_8c7d = { d8 15 [2] ac 0d [2] eb 0f [2] ac 1e [2] e2 12 [2] ee 18 [2] f9 13 [2] e2 5d [2] df }

  condition:
    any of them
}