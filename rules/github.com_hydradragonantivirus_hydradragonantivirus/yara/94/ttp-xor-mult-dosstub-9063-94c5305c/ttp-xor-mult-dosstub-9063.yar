rule TTP_XOR_MULT_DOSStub_9063 {
  strings:
    $key_9063 = { c4 0b [2] b0 13 [2] f7 11 [2] b0 00 [2] fe 0c [2] f2 06 [2] e5 0d [2] fe 43 [2] c3 }

  condition:
    any of them
}