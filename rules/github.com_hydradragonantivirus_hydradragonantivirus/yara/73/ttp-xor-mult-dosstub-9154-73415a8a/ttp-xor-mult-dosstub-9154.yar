rule TTP_XOR_MULT_DOSStub_9154 {
  strings:
    $key_9154 = { c5 3c [2] b1 24 [2] f6 26 [2] b1 37 [2] ff 3b [2] f3 31 [2] e4 3a [2] ff 74 [2] c2 }

  condition:
    any of them
}