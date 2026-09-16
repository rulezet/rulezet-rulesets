rule TTP_XOR_MULT_DOSStub_8c36 {
  strings:
    $key_8c36 = { d8 5e [2] ac 46 [2] eb 44 [2] ac 55 [2] e2 59 [2] ee 53 [2] f9 58 [2] e2 16 [2] df }

  condition:
    any of them
}