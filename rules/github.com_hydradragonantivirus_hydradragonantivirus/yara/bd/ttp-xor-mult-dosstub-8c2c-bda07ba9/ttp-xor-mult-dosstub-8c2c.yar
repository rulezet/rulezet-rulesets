rule TTP_XOR_MULT_DOSStub_8c2c {
  strings:
    $key_8c2c = { d8 44 [2] ac 5c [2] eb 5e [2] ac 4f [2] e2 43 [2] ee 49 [2] f9 42 [2] e2 0c [2] df }

  condition:
    any of them
}