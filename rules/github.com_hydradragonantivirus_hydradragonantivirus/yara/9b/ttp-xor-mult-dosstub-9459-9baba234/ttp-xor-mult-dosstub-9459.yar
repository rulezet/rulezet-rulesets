rule TTP_XOR_MULT_DOSStub_9459 {
  strings:
    $key_9459 = { c0 31 [2] b4 29 [2] f3 2b [2] b4 3a [2] fa 36 [2] f6 3c [2] e1 37 [2] fa 79 [2] c7 }

  condition:
    any of them
}