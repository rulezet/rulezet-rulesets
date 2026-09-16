rule TTP_XOR_MULT_DOSStub_8c19 {
  strings:
    $key_8c19 = { d8 71 [2] ac 69 [2] eb 6b [2] ac 7a [2] e2 76 [2] ee 7c [2] f9 77 [2] e2 39 [2] df }

  condition:
    any of them
}