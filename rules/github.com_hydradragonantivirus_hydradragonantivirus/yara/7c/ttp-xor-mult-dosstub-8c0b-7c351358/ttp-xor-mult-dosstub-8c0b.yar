rule TTP_XOR_MULT_DOSStub_8c0b {
  strings:
    $key_8c0b = { d8 63 [2] ac 7b [2] eb 79 [2] ac 68 [2] e2 64 [2] ee 6e [2] f9 65 [2] e2 2b [2] df }

  condition:
    any of them
}