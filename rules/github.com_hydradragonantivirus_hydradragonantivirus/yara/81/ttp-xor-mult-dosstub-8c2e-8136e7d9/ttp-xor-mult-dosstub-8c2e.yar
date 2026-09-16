rule TTP_XOR_MULT_DOSStub_8c2e {
  strings:
    $key_8c2e = { d8 46 [2] ac 5e [2] eb 5c [2] ac 4d [2] e2 41 [2] ee 4b [2] f9 40 [2] e2 0e [2] df }

  condition:
    any of them
}