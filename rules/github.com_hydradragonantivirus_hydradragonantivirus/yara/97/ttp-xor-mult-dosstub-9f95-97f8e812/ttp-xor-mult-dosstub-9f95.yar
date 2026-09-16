rule TTP_XOR_MULT_DOSStub_9f95 {
  strings:
    $key_9f95 = { cb fd [2] bf e5 [2] f8 e7 [2] bf f6 [2] f1 fa [2] fd f0 [2] ea fb [2] f1 b5 [2] cc }

  condition:
    any of them
}