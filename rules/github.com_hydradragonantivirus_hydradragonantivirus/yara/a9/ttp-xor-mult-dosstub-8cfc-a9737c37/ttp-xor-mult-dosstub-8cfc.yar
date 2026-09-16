rule TTP_XOR_MULT_DOSStub_8cfc {
  strings:
    $key_8cfc = { d8 94 [2] ac 8c [2] eb 8e [2] ac 9f [2] e2 93 [2] ee 99 [2] f9 92 [2] e2 dc [2] df }

  condition:
    any of them
}