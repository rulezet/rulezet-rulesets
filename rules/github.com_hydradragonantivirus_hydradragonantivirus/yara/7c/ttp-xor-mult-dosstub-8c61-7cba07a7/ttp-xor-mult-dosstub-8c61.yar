rule TTP_XOR_MULT_DOSStub_8c61 {
  strings:
    $key_8c61 = { d8 09 [2] ac 11 [2] eb 13 [2] ac 02 [2] e2 0e [2] ee 04 [2] f9 0f [2] e2 41 [2] df }

  condition:
    any of them
}