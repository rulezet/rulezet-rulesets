rule TTP_XOR_MULT_DOSStub_8c5a {
  strings:
    $key_8c5a = { d8 32 [2] ac 2a [2] eb 28 [2] ac 39 [2] e2 35 [2] ee 3f [2] f9 34 [2] e2 7a [2] df }

  condition:
    any of them
}