rule TTP_XOR_MULT_DOSStub_8c10 {
  strings:
    $key_8c10 = { d8 78 [2] ac 60 [2] eb 62 [2] ac 73 [2] e2 7f [2] ee 75 [2] f9 7e [2] e2 30 [2] df }

  condition:
    any of them
}