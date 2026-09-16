rule TTP_XOR_MULT_DOSStub_d539 {
  strings:
    $key_d539 = { 81 51 [2] f5 49 [2] b2 4b [2] f5 5a [2] bb 56 [2] b7 5c [2] a0 57 [2] bb 19 [2] 86 }

  condition:
    any of them
}