rule TTP_XOR_MULT_DOSStub_8c78 {
  strings:
    $key_8c78 = { d8 10 [2] ac 08 [2] eb 0a [2] ac 1b [2] e2 17 [2] ee 1d [2] f9 16 [2] e2 58 [2] df }

  condition:
    any of them
}