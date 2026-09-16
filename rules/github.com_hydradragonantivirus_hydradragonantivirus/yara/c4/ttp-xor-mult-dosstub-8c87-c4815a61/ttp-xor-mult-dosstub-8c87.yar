rule TTP_XOR_MULT_DOSStub_8c87 {
  strings:
    $key_8c87 = { d8 ef [2] ac f7 [2] eb f5 [2] ac e4 [2] e2 e8 [2] ee e2 [2] f9 e9 [2] e2 a7 [2] df }

  condition:
    any of them
}