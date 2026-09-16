rule TTP_XOR_MULT_DOSStub_9524 {
  strings:
    $key_9524 = { c1 4c [2] b5 54 [2] f2 56 [2] b5 47 [2] fb 4b [2] f7 41 [2] e0 4a [2] fb 04 [2] c6 }

  condition:
    any of them
}