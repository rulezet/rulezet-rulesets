rule TTP_XOR_MULT_DOSStub_8c40 {
  strings:
    $key_8c40 = { d8 28 [2] ac 30 [2] eb 32 [2] ac 23 [2] e2 2f [2] ee 25 [2] f9 2e [2] e2 60 [2] df }

  condition:
    any of them
}