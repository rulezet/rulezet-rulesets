rule TTP_XOR_MULT_DOSStub_9692 {
  strings:
    $key_9692 = { c2 fa [2] b6 e2 [2] f1 e0 [2] b6 f1 [2] f8 fd [2] f4 f7 [2] e3 fc [2] f8 b2 [2] c5 }

  condition:
    any of them
}