rule TTP_XOR_MULT_DOSStub_8c4b {
  strings:
    $key_8c4b = { d8 23 [2] ac 3b [2] eb 39 [2] ac 28 [2] e2 24 [2] ee 2e [2] f9 25 [2] e2 6b [2] df }

  condition:
    any of them
}