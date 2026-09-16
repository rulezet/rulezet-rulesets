rule TTP_XOR_MULT_DOSStub_9045 {
  strings:
    $key_9045 = { c4 2d [2] b0 35 [2] f7 37 [2] b0 26 [2] fe 2a [2] f2 20 [2] e5 2b [2] fe 65 [2] c3 }

  condition:
    any of them
}