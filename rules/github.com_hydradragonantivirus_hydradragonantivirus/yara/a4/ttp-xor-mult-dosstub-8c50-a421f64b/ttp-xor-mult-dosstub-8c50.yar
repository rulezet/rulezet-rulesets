rule TTP_XOR_MULT_DOSStub_8c50 {
  strings:
    $key_8c50 = { d8 38 [2] ac 20 [2] eb 22 [2] ac 33 [2] e2 3f [2] ee 35 [2] f9 3e [2] e2 70 [2] df }

  condition:
    any of them
}