rule TTP_XOR_MULT_DOSStub_8c68 {
  strings:
    $key_8c68 = { d8 00 [2] ac 18 [2] eb 1a [2] ac 0b [2] e2 07 [2] ee 0d [2] f9 06 [2] e2 48 [2] df }

  condition:
    any of them
}