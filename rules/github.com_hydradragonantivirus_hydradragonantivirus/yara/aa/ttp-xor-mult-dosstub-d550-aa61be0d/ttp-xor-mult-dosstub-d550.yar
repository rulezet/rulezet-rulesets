rule TTP_XOR_MULT_DOSStub_d550 {
  strings:
    $key_d550 = { 81 38 [2] f5 20 [2] b2 22 [2] f5 33 [2] bb 3f [2] b7 35 [2] a0 3e [2] bb 70 [2] 86 }

  condition:
    any of them
}