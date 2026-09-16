rule TTP_XOR_MULT_DOSStub_8995 {
  strings:
    $key_8995 = { dd fd [2] a9 e5 [2] ee e7 [2] a9 f6 [2] e7 fa [2] eb f0 [2] fc fb [2] e7 b5 [2] da }

  condition:
    any of them
}