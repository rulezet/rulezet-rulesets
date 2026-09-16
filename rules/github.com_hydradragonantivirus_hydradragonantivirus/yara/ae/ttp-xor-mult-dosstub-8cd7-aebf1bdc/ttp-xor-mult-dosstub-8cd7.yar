rule TTP_XOR_MULT_DOSStub_8cd7 {
  strings:
    $key_8cd7 = { d8 bf [2] ac a7 [2] eb a5 [2] ac b4 [2] e2 b8 [2] ee b2 [2] f9 b9 [2] e2 f7 [2] df }

  condition:
    any of them
}