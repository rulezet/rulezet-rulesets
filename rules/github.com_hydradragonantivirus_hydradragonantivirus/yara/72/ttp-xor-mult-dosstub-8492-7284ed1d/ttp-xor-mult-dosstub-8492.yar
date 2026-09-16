rule TTP_XOR_MULT_DOSStub_8492 {
  strings:
    $key_8492 = { d0 fa [2] a4 e2 [2] e3 e0 [2] a4 f1 [2] ea fd [2] e6 f7 [2] f1 fc [2] ea b2 [2] d7 }

  condition:
    any of them
}