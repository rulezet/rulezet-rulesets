rule TTP_XOR_MULT_DOSStub_8c2a {
  strings:
    $key_8c2a = { d8 42 [2] ac 5a [2] eb 58 [2] ac 49 [2] e2 45 [2] ee 4f [2] f9 44 [2] e2 0a [2] df }

  condition:
    any of them
}