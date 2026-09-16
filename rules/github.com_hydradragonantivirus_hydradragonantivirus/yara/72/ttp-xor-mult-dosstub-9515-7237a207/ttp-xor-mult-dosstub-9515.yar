rule TTP_XOR_MULT_DOSStub_9515 {
  strings:
    $key_9515 = { c1 7d [2] b5 65 [2] f2 67 [2] b5 76 [2] fb 7a [2] f7 70 [2] e0 7b [2] fb 35 [2] c6 }

  condition:
    any of them
}