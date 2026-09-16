rule TTP_XOR_MULT_DOSStub_9492 {
  strings:
    $key_9492 = { c0 fa [2] b4 e2 [2] f3 e0 [2] b4 f1 [2] fa fd [2] f6 f7 [2] e1 fc [2] fa b2 [2] c7 }

  condition:
    any of them
}