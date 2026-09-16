rule TTP_XOR_MULT_DOSStub_8c00 {
  strings:
    $key_8c00 = { d8 68 [2] ac 70 [2] eb 72 [2] ac 63 [2] e2 6f [2] ee 65 [2] f9 6e [2] e2 20 [2] df }

  condition:
    any of them
}