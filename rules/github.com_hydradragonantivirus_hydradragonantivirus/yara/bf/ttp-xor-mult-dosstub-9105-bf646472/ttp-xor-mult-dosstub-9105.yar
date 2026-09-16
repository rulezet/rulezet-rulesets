rule TTP_XOR_MULT_DOSStub_9105 {
  strings:
    $key_9105 = { c5 6d [2] b1 75 [2] f6 77 [2] b1 66 [2] ff 6a [2] f3 60 [2] e4 6b [2] ff 25 [2] c2 }

  condition:
    any of them
}