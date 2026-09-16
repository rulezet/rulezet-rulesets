rule TTP_XOR_MULT_DOSStub_8c34 {
  strings:
    $key_8c34 = { d8 5c [2] ac 44 [2] eb 46 [2] ac 57 [2] e2 5b [2] ee 51 [2] f9 5a [2] e2 14 [2] df }

  condition:
    any of them
}