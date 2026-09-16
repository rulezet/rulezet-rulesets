rule TTP_XOR_MULT_DOSStub_8c59 {
  strings:
    $key_8c59 = { d8 31 [2] ac 29 [2] eb 2b [2] ac 3a [2] e2 36 [2] ee 3c [2] f9 37 [2] e2 79 [2] df }

  condition:
    any of them
}