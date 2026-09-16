rule TTP_XOR_MULT_DOSStub_8cd0 {
  strings:
    $key_8cd0 = { d8 b8 [2] ac a0 [2] eb a2 [2] ac b3 [2] e2 bf [2] ee b5 [2] f9 be [2] e2 f0 [2] df }

  condition:
    any of them
}