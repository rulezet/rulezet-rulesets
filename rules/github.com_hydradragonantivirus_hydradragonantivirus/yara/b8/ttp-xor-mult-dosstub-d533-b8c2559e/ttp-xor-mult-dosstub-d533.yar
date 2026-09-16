rule TTP_XOR_MULT_DOSStub_d533 {
  strings:
    $key_d533 = { 81 5b [2] f5 43 [2] b2 41 [2] f5 50 [2] bb 5c [2] b7 56 [2] a0 5d [2] bb 13 [2] 86 }

  condition:
    any of them
}