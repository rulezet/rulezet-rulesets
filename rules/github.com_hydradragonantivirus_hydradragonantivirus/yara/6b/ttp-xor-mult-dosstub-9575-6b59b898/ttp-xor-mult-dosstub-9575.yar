rule TTP_XOR_MULT_DOSStub_9575 {
  strings:
    $key_9575 = { c1 1d [2] b5 05 [2] f2 07 [2] b5 16 [2] fb 1a [2] f7 10 [2] e0 1b [2] fb 55 [2] c6 }

  condition:
    any of them
}