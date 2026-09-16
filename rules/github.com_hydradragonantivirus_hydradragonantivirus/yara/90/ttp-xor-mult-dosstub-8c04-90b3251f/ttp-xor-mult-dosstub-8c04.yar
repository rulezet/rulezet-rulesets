rule TTP_XOR_MULT_DOSStub_8c04 {
  strings:
    $key_8c04 = { d8 6c [2] ac 74 [2] eb 76 [2] ac 67 [2] e2 6b [2] ee 61 [2] f9 6a [2] e2 24 [2] df }

  condition:
    any of them
}