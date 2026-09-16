rule TTP_XOR_MULT_DOSStub_9542 {
  strings:
    $key_9542 = { c1 2a [2] b5 32 [2] f2 30 [2] b5 21 [2] fb 2d [2] f7 27 [2] e0 2c [2] fb 62 [2] c6 }

  condition:
    any of them
}