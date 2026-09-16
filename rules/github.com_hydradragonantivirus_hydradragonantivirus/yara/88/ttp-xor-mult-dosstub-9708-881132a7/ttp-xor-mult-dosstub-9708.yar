rule TTP_XOR_MULT_DOSStub_9708 {
  strings:
    $key_9708 = { c3 60 [2] b7 78 [2] f0 7a [2] b7 6b [2] f9 67 [2] f5 6d [2] e2 66 [2] f9 28 [2] c4 }

  condition:
    any of them
}