rule TTP_XOR_MULT_DOSStub_8c22 {
  strings:
    $key_8c22 = { d8 4a [2] ac 52 [2] eb 50 [2] ac 41 [2] e2 4d [2] ee 47 [2] f9 4c [2] e2 02 [2] df }

  condition:
    any of them
}