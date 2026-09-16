rule TTP_XOR_MULT_DOSStub_8c48 {
  strings:
    $key_8c48 = { d8 20 [2] ac 38 [2] eb 3a [2] ac 2b [2] e2 27 [2] ee 2d [2] f9 26 [2] e2 68 [2] df }

  condition:
    any of them
}