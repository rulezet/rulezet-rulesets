rule TTP_XOR_MULT_DOSStub_8c11 {
  strings:
    $key_8c11 = { d8 79 [2] ac 61 [2] eb 63 [2] ac 72 [2] e2 7e [2] ee 74 [2] f9 7f [2] e2 31 [2] df }

  condition:
    any of them
}