rule TTP_XOR_MULT_DOSStub_8c13 {
  strings:
    $key_8c13 = { d8 7b [2] ac 63 [2] eb 61 [2] ac 70 [2] e2 7c [2] ee 76 [2] f9 7d [2] e2 33 [2] df }

  condition:
    any of them
}