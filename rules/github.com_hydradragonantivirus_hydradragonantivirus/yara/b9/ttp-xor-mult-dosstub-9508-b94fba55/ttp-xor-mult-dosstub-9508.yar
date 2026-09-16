rule TTP_XOR_MULT_DOSStub_9508 {
  strings:
    $key_9508 = { c1 60 [2] b5 78 [2] f2 7a [2] b5 6b [2] fb 67 [2] f7 6d [2] e0 66 [2] fb 28 [2] c6 }

  condition:
    any of them
}