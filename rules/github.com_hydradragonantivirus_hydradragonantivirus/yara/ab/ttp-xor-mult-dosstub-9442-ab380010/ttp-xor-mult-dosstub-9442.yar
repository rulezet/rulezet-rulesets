rule TTP_XOR_MULT_DOSStub_9442 {
  strings:
    $key_9442 = { c0 2a [2] b4 32 [2] f3 30 [2] b4 21 [2] fa 2d [2] f6 27 [2] e1 2c [2] fa 62 [2] c7 }

  condition:
    any of them
}