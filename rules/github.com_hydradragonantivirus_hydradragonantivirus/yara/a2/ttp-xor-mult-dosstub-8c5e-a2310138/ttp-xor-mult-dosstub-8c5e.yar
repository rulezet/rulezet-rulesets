rule TTP_XOR_MULT_DOSStub_8c5e {
  strings:
    $key_8c5e = { d8 36 [2] ac 2e [2] eb 2c [2] ac 3d [2] e2 31 [2] ee 3b [2] f9 30 [2] e2 7e [2] df }

  condition:
    any of them
}