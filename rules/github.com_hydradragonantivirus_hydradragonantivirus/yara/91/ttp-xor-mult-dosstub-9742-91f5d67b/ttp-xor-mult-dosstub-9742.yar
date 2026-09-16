rule TTP_XOR_MULT_DOSStub_9742 {
  strings:
    $key_9742 = { c3 2a [2] b7 32 [2] f0 30 [2] b7 21 [2] f9 2d [2] f5 27 [2] e2 2c [2] f9 62 [2] c4 }

  condition:
    any of them
}