rule TTP_XOR_MULT_DOSStub_8cf0 {
  strings:
    $key_8cf0 = { d8 98 [2] ac 80 [2] eb 82 [2] ac 93 [2] e2 9f [2] ee 95 [2] f9 9e [2] e2 d0 [2] df }

  condition:
    any of them
}