rule TTP_XOR_MULT_DOSStub_9495 {
  strings:
    $key_9495 = { c0 fd [2] b4 e5 [2] f3 e7 [2] b4 f6 [2] fa fa [2] f6 f0 [2] e1 fb [2] fa b5 [2] c7 }

  condition:
    any of them
}