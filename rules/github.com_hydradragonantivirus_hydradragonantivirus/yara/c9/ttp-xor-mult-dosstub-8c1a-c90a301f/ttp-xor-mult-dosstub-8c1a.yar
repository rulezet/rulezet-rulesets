rule TTP_XOR_MULT_DOSStub_8c1a {
  strings:
    $key_8c1a = { d8 72 [2] ac 6a [2] eb 68 [2] ac 79 [2] e2 75 [2] ee 7f [2] f9 74 [2] e2 3a [2] df }

  condition:
    any of them
}