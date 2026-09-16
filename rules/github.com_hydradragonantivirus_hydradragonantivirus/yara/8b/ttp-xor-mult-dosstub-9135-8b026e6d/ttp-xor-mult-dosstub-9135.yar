rule TTP_XOR_MULT_DOSStub_9135 {
  strings:
    $key_9135 = { c5 5d [2] b1 45 [2] f6 47 [2] b1 56 [2] ff 5a [2] f3 50 [2] e4 5b [2] ff 15 [2] c2 }

  condition:
    any of them
}