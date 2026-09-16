rule TTP_XOR_MULT_DOSStub_9454 {
  strings:
    $key_9454 = { c0 3c [2] b4 24 [2] f3 26 [2] b4 37 [2] fa 3b [2] f6 31 [2] e1 3a [2] fa 74 [2] c7 }

  condition:
    any of them
}