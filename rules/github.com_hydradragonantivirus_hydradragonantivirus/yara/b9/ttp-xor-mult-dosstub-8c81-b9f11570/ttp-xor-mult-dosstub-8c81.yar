rule TTP_XOR_MULT_DOSStub_8c81 {
  strings:
    $key_8c81 = { d8 e9 [2] ac f1 [2] eb f3 [2] ac e2 [2] e2 ee [2] ee e4 [2] f9 ef [2] e2 a1 [2] df }

  condition:
    any of them
}