rule TTP_XOR_MULT_DOSStub_9474 {
  strings:
    $key_9474 = { c0 1c [2] b4 04 [2] f3 06 [2] b4 17 [2] fa 1b [2] f6 11 [2] e1 1a [2] fa 54 [2] c7 }

  condition:
    any of them
}