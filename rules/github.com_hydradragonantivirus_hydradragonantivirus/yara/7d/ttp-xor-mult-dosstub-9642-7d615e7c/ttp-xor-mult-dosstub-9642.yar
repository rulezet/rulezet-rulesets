rule TTP_XOR_MULT_DOSStub_9642 {
  strings:
    $key_9642 = { c2 2a [2] b6 32 [2] f1 30 [2] b6 21 [2] f8 2d [2] f4 27 [2] e3 2c [2] f8 62 [2] c5 }

  condition:
    any of them
}