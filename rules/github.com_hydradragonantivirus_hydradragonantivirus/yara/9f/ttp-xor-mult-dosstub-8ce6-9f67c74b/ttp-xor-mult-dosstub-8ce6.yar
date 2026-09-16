rule TTP_XOR_MULT_DOSStub_8ce6 {
  strings:
    $key_8ce6 = { d8 8e [2] ac 96 [2] eb 94 [2] ac 85 [2] e2 89 [2] ee 83 [2] f9 88 [2] e2 c6 [2] df }

  condition:
    any of them
}