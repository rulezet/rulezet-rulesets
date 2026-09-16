rule TTP_XOR_MULT_DOSStub_8c16 {
  strings:
    $key_8c16 = { d8 7e [2] ac 66 [2] eb 64 [2] ac 75 [2] e2 79 [2] ee 73 [2] f9 78 [2] e2 36 [2] df }

  condition:
    any of them
}