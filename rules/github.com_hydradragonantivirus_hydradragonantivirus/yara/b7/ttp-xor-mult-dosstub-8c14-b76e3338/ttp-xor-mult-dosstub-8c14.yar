rule TTP_XOR_MULT_DOSStub_8c14 {
  strings:
    $key_8c14 = { d8 7c [2] ac 64 [2] eb 66 [2] ac 77 [2] e2 7b [2] ee 71 [2] f9 7a [2] e2 34 [2] df }

  condition:
    any of them
}