rule TTP_XOR_MULT_DOSStub_9522 {
  strings:
    $key_9522 = { c1 4a [2] b5 52 [2] f2 50 [2] b5 41 [2] fb 4d [2] f7 47 [2] e0 4c [2] fb 02 [2] c6 }

  condition:
    any of them
}