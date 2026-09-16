rule TTP_XOR_MULT_DOSStub_8c58 {
  strings:
    $key_8c58 = { d8 30 [2] ac 28 [2] eb 2a [2] ac 3b [2] e2 37 [2] ee 3d [2] f9 36 [2] e2 78 [2] df }

  condition:
    any of them
}