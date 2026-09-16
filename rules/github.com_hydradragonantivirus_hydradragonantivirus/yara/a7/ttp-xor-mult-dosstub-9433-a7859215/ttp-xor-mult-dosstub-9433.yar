rule TTP_XOR_MULT_DOSStub_9433 {
  strings:
    $key_9433 = { c0 5b [2] b4 43 [2] f3 41 [2] b4 50 [2] fa 5c [2] f6 56 [2] e1 5d [2] fa 13 [2] c7 }

  condition:
    any of them
}