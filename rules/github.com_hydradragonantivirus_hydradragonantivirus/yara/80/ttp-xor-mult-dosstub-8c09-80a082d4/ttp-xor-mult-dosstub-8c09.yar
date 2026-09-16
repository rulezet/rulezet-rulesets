rule TTP_XOR_MULT_DOSStub_8c09 {
  strings:
    $key_8c09 = { d8 61 [2] ac 79 [2] eb 7b [2] ac 6a [2] e2 66 [2] ee 6c [2] f9 67 [2] e2 29 [2] df }

  condition:
    any of them
}