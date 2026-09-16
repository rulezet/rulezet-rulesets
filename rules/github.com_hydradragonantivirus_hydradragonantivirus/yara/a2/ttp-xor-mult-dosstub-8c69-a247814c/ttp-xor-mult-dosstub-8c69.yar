rule TTP_XOR_MULT_DOSStub_8c69 {
  strings:
    $key_8c69 = { d8 01 [2] ac 19 [2] eb 1b [2] ac 0a [2] e2 06 [2] ee 0c [2] f9 07 [2] e2 49 [2] df }

  condition:
    any of them
}