rule TTP_XOR_MULT_DOSStub_9342 {
  strings:
    $key_9342 = { c7 2a [2] b3 32 [2] f4 30 [2] b3 21 [2] fd 2d [2] f1 27 [2] e6 2c [2] fd 62 [2] c0 }

  condition:
    any of them
}