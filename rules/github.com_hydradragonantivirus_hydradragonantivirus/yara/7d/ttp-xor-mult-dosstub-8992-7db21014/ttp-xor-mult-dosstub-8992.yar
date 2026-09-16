rule TTP_XOR_MULT_DOSStub_8992 {
  strings:
    $key_8992 = { dd fa [2] a9 e2 [2] ee e0 [2] a9 f1 [2] e7 fd [2] eb f7 [2] fc fc [2] e7 b2 [2] da }

  condition:
    any of them
}