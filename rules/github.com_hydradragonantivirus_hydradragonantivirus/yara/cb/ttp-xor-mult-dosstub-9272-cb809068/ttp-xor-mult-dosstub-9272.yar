rule TTP_XOR_MULT_DOSStub_9272 {
  strings:
    $key_9272 = { c6 1a [2] b2 02 [2] f5 00 [2] b2 11 [2] fc 1d [2] f0 17 [2] e7 1c [2] fc 52 [2] c1 }

  condition:
    any of them
}