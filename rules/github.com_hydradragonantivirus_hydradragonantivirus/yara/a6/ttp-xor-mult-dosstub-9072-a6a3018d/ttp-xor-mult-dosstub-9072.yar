rule TTP_XOR_MULT_DOSStub_9072 {
  strings:
    $key_9072 = { c4 1a [2] b0 02 [2] f7 00 [2] b0 11 [2] fe 1d [2] f2 17 [2] e5 1c [2] fe 52 [2] c3 }

  condition:
    any of them
}