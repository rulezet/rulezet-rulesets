rule TTP_XOR_MULT_DOSStub_9248 {
  strings:
    $key_9248 = { c6 20 [2] b2 38 [2] f5 3a [2] b2 2b [2] fc 27 [2] f0 2d [2] e7 26 [2] fc 68 [2] c1 }

  condition:
    any of them
}