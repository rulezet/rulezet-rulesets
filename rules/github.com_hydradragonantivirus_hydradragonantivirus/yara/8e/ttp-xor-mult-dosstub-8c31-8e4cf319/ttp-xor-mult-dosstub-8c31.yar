rule TTP_XOR_MULT_DOSStub_8c31 {
  strings:
    $key_8c31 = { d8 59 [2] ac 41 [2] eb 43 [2] ac 52 [2] e2 5e [2] ee 54 [2] f9 5f [2] e2 11 [2] df }

  condition:
    any of them
}