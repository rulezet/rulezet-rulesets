rule TTP_XOR_MULT_DOSStub_9074 {
  strings:
    $key_9074 = { c4 1c [2] b0 04 [2] f7 06 [2] b0 17 [2] fe 1b [2] f2 11 [2] e5 1a [2] fe 54 [2] c3 }

  condition:
    any of them
}