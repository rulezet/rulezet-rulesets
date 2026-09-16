rule TTP_XOR_MULT_DOSStub_d546 {
  strings:
    $key_d546 = { 81 2e [2] f5 36 [2] b2 34 [2] f5 25 [2] bb 29 [2] b7 23 [2] a0 28 [2] bb 66 [2] 86 }

  condition:
    any of them
}