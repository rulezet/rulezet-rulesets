rule TTP_XOR_MULT_DOSStub_8c8f {
  strings:
    $key_8c8f = { d8 e7 [2] ac ff [2] eb fd [2] ac ec [2] e2 e0 [2] ee ea [2] f9 e1 [2] e2 af [2] df }

  condition:
    any of them
}