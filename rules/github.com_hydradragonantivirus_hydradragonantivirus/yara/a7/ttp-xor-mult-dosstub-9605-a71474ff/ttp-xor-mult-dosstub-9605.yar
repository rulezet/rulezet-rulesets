rule TTP_XOR_MULT_DOSStub_9605 {
  strings:
    $key_9605 = { c2 6d [2] b6 75 [2] f1 77 [2] b6 66 [2] f8 6a [2] f4 60 [2] e3 6b [2] f8 25 [2] c5 }

  condition:
    any of them
}