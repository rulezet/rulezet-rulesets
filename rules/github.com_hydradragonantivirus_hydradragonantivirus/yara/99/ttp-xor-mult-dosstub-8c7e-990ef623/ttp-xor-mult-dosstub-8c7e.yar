rule TTP_XOR_MULT_DOSStub_8c7e {
  strings:
    $key_8c7e = { d8 16 [2] ac 0e [2] eb 0c [2] ac 1d [2] e2 11 [2] ee 1b [2] f9 10 [2] e2 5e [2] df }

  condition:
    any of them
}