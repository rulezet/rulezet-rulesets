rule TTP_XOR_MULT_DOSStub_8c32 {
  strings:
    $key_8c32 = { d8 5a [2] ac 42 [2] eb 40 [2] ac 51 [2] e2 5d [2] ee 57 [2] f9 5c [2] e2 12 [2] df }

  condition:
    any of them
}