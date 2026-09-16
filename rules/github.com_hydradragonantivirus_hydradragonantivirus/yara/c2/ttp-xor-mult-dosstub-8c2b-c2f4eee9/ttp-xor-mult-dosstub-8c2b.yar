rule TTP_XOR_MULT_DOSStub_8c2b {
  strings:
    $key_8c2b = { d8 43 [2] ac 5b [2] eb 59 [2] ac 48 [2] e2 44 [2] ee 4e [2] f9 45 [2] e2 0b [2] df }

  condition:
    any of them
}