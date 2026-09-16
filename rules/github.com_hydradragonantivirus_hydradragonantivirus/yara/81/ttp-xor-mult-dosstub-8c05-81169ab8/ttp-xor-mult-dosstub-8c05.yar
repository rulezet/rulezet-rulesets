rule TTP_XOR_MULT_DOSStub_8c05 {
  strings:
    $key_8c05 = { d8 6d [2] ac 75 [2] eb 77 [2] ac 66 [2] e2 6a [2] ee 60 [2] f9 6b [2] e2 25 [2] df }

  condition:
    any of them
}