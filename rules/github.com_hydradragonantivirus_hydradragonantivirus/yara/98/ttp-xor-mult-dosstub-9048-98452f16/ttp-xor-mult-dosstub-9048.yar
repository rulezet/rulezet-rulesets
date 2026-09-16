rule TTP_XOR_MULT_DOSStub_9048 {
  strings:
    $key_9048 = { c4 20 [2] b0 38 [2] f7 3a [2] b0 2b [2] fe 27 [2] f2 2d [2] e5 26 [2] fe 68 [2] c3 }

  condition:
    any of them
}