rule TTP_XOR_MULT_DOSStub_8c5d {
  strings:
    $key_8c5d = { d8 35 [2] ac 2d [2] eb 2f [2] ac 3e [2] e2 32 [2] ee 38 [2] f9 33 [2] e2 7d [2] df }

  condition:
    any of them
}