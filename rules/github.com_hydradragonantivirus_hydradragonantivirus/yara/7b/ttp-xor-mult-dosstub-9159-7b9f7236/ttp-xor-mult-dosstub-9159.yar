rule TTP_XOR_MULT_DOSStub_9159 {
  strings:
    $key_9159 = { c5 31 [2] b1 29 [2] f6 2b [2] b1 3a [2] ff 36 [2] f3 3c [2] e4 37 [2] ff 79 [2] c2 }

  condition:
    any of them
}