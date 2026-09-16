rule TTP_XOR_MULT_DOSStub_8c8a {
  strings:
    $key_8c8a = { d8 e2 [2] ac fa [2] eb f8 [2] ac e9 [2] e2 e5 [2] ee ef [2] f9 e4 [2] e2 aa [2] df }

  condition:
    any of them
}