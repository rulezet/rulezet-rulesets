rule TTP_XOR_MULT_DOSStub_8c92 {
  strings:
    $key_8c92 = { d8 fa [2] ac e2 [2] eb e0 [2] ac f1 [2] e2 fd [2] ee f7 [2] f9 fc [2] e2 b2 [2] df }

  condition:
    any of them
}