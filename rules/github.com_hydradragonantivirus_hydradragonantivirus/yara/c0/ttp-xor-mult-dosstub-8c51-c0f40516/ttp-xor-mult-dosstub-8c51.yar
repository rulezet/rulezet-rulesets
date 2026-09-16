rule TTP_XOR_MULT_DOSStub_8c51 {
  strings:
    $key_8c51 = { d8 39 [2] ac 21 [2] eb 23 [2] ac 32 [2] e2 3e [2] ee 34 [2] f9 3f [2] e2 71 [2] df }

  condition:
    any of them
}