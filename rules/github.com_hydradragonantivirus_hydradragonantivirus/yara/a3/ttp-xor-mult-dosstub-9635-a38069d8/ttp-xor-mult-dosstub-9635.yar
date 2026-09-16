rule TTP_XOR_MULT_DOSStub_9635 {
  strings:
    $key_9635 = { c2 5d [2] b6 45 [2] f1 47 [2] b6 56 [2] f8 5a [2] f4 50 [2] e3 5b [2] f8 15 [2] c5 }

  condition:
    any of them
}