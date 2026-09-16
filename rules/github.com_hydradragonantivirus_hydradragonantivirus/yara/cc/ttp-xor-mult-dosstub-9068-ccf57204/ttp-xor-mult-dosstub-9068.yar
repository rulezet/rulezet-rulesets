rule TTP_XOR_MULT_DOSStub_9068 {
  strings:
    $key_9068 = { c4 00 [2] b0 18 [2] f7 1a [2] b0 0b [2] fe 07 [2] f2 0d [2] e5 06 [2] fe 48 [2] c3 }

  condition:
    any of them
}