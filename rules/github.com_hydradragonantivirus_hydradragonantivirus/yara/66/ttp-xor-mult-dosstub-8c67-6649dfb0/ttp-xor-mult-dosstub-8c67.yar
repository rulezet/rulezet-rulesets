rule TTP_XOR_MULT_DOSStub_8c67 {
  strings:
    $key_8c67 = { d8 0f [2] ac 17 [2] eb 15 [2] ac 04 [2] e2 08 [2] ee 02 [2] f9 09 [2] e2 47 [2] df }

  condition:
    any of them
}