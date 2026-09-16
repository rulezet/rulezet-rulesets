rule TTP_XOR_MULT_DOSStub_8c18 {
  strings:
    $key_8c18 = { d8 70 [2] ac 68 [2] eb 6a [2] ac 7b [2] e2 77 [2] ee 7d [2] f9 76 [2] e2 38 [2] df }

  condition:
    any of them
}