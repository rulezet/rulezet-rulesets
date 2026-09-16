rule TTP_XOR_MULT_DOSStub_8c62 {
  strings:
    $key_8c62 = { d8 0a [2] ac 12 [2] eb 10 [2] ac 01 [2] e2 0d [2] ee 07 [2] f9 0c [2] e2 42 [2] df }

  condition:
    any of them
}