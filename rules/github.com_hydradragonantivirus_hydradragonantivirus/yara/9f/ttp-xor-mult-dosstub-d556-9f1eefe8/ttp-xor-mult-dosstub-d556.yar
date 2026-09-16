rule TTP_XOR_MULT_DOSStub_d556 {
  strings:
    $key_d556 = { 81 3e [2] f5 26 [2] b2 24 [2] f5 35 [2] bb 39 [2] b7 33 [2] a0 38 [2] bb 76 [2] 86 }

  condition:
    any of them
}