rule TTP_XOR_MULT_DOSStub_8cee {
  strings:
    $key_8cee = { d8 86 [2] ac 9e [2] eb 9c [2] ac 8d [2] e2 81 [2] ee 8b [2] f9 80 [2] e2 ce [2] df }

  condition:
    any of them
}