rule TTP_XOR_MULT_DOSStub_8c5c {
  strings:
    $key_8c5c = { d8 34 [2] ac 2c [2] eb 2e [2] ac 3f [2] e2 33 [2] ee 39 [2] f9 32 [2] e2 7c [2] df }

  condition:
    any of them
}