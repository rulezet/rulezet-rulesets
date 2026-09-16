rule TTP_XOR_MULT_DOSStub_8c54 {
  strings:
    $key_8c54 = { d8 3c [2] ac 24 [2] eb 26 [2] ac 37 [2] e2 3b [2] ee 31 [2] f9 3a [2] e2 74 [2] df }

  condition:
    any of them
}