rule TTP_XOR_MULT_DOSStub_9648 {
  strings:
    $key_9648 = { c2 20 [2] b6 38 [2] f1 3a [2] b6 2b [2] f8 27 [2] f4 2d [2] e3 26 [2] f8 68 [2] c5 }

  condition:
    any of them
}