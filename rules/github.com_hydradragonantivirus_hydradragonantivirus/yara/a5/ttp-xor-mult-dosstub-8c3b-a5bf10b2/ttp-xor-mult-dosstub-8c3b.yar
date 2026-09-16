rule TTP_XOR_MULT_DOSStub_8c3b {
  strings:
    $key_8c3b = { d8 53 [2] ac 4b [2] eb 49 [2] ac 58 [2] e2 54 [2] ee 5e [2] f9 55 [2] e2 1b [2] df }

  condition:
    any of them
}