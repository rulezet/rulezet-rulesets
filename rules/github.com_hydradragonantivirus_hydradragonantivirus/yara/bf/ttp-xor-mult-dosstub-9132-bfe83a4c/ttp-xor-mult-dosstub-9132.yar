rule TTP_XOR_MULT_DOSStub_9132 {
  strings:
    $key_9132 = { c5 5a [2] b1 42 [2] f6 40 [2] b1 51 [2] ff 5d [2] f3 57 [2] e4 5c [2] ff 12 [2] c2 }

  condition:
    any of them
}