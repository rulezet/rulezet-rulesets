rule TTP_XOR_MULT_DOSStub_9578 {
  strings:
    $key_9578 = { c1 10 [2] b5 08 [2] f2 0a [2] b5 1b [2] fb 17 [2] f7 1d [2] e0 16 [2] fb 58 [2] c6 }

  condition:
    any of them
}