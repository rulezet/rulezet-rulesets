rule TTP_XOR_MULT_DOSStub_9463 {
  strings:
    $key_9463 = { c0 0b [2] b4 13 [2] f3 11 [2] b4 00 [2] fa 0c [2] f6 06 [2] e1 0d [2] fa 43 [2] c7 }

  condition:
    any of them
}