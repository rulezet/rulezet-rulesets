rule TTP_XOR_MULT_DOSStub_9535 {
  strings:
    $key_9535 = { c1 5d [2] b5 45 [2] f2 47 [2] b5 56 [2] fb 5a [2] f7 50 [2] e0 5b [2] fb 15 [2] c6 }

  condition:
    any of them
}