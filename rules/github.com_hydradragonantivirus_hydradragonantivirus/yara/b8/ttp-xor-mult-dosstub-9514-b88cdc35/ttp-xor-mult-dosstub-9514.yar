rule TTP_XOR_MULT_DOSStub_9514 {
  strings:
    $key_9514 = { c1 7c [2] b5 64 [2] f2 66 [2] b5 77 [2] fb 7b [2] f7 71 [2] e0 7a [2] fb 34 [2] c6 }

  condition:
    any of them
}