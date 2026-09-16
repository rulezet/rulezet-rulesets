rule TTP_XOR_MULT_DOSStub_8c71 {
  strings:
    $key_8c71 = { d8 19 [2] ac 01 [2] eb 03 [2] ac 12 [2] e2 1e [2] ee 14 [2] f9 1f [2] e2 51 [2] df }

  condition:
    any of them
}