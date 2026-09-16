rule TTP_XOR_MULT_DOSStub_8c1e {
  strings:
    $key_8c1e = { d8 76 [2] ac 6e [2] eb 6c [2] ac 7d [2] e2 71 [2] ee 7b [2] f9 70 [2] e2 3e [2] df }

  condition:
    any of them
}