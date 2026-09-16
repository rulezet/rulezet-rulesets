rule TTP_XOR_MULT_DOSStub_9075 {
  strings:
    $key_9075 = { c4 1d [2] b0 05 [2] f7 07 [2] b0 16 [2] fe 1a [2] f2 10 [2] e5 1b [2] fe 55 [2] c3 }

  condition:
    any of them
}