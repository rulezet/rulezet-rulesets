rule TTP_XOR_MULT_DOSStub_9491 {
  strings:
    $key_9491 = { c0 f9 [2] b4 e1 [2] f3 e3 [2] b4 f2 [2] fa fe [2] f6 f4 [2] e1 ff [2] fa b1 [2] c7 }

  condition:
    any of them
}