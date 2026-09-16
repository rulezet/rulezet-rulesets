rule TTP_XOR_MULT_DOSStub_8c27 {
  strings:
    $key_8c27 = { d8 4f [2] ac 57 [2] eb 55 [2] ac 44 [2] e2 48 [2] ee 42 [2] f9 49 [2] e2 07 [2] df }

  condition:
    any of them
}