rule TTP_XOR_MULT_DOSStub_8c7a {
  strings:
    $key_8c7a = { d8 12 [2] ac 0a [2] eb 08 [2] ac 19 [2] e2 15 [2] ee 1f [2] f9 14 [2] e2 5a [2] df }

  condition:
    any of them
}