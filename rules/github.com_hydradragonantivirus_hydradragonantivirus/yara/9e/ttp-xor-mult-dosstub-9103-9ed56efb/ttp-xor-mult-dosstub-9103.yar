rule TTP_XOR_MULT_DOSStub_9103 {
  strings:
    $key_9103 = { c5 6b [2] b1 73 [2] f6 71 [2] b1 60 [2] ff 6c [2] f3 66 [2] e4 6d [2] ff 23 [2] c2 }

  condition:
    any of them
}