rule TTP_XOR_MULT_DOSStub_8c7b {
  strings:
    $key_8c7b = { d8 13 [2] ac 0b [2] eb 09 [2] ac 18 [2] e2 14 [2] ee 1e [2] f9 15 [2] e2 5b [2] df }

  condition:
    any of them
}