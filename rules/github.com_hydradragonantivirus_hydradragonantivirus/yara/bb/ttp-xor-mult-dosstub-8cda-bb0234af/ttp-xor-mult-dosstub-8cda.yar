rule TTP_XOR_MULT_DOSStub_8cda {
  strings:
    $key_8cda = { d8 b2 [2] ac aa [2] eb a8 [2] ac b9 [2] e2 b5 [2] ee bf [2] f9 b4 [2] e2 fa [2] df }

  condition:
    any of them
}