rule TTP_XOR_MULT_DOSStub_9502 {
  strings:
    $key_9502 = { c1 6a [2] b5 72 [2] f2 70 [2] b5 61 [2] fb 6d [2] f7 67 [2] e0 6c [2] fb 22 [2] c6 }

  condition:
    any of them
}