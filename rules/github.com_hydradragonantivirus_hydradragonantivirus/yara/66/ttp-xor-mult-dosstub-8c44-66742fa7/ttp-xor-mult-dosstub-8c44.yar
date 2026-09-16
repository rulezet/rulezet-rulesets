rule TTP_XOR_MULT_DOSStub_8c44 {
  strings:
    $key_8c44 = { d8 2c [2] ac 34 [2] eb 36 [2] ac 27 [2] e2 2b [2] ee 21 [2] f9 2a [2] e2 64 [2] df }

  condition:
    any of them
}