rule TTP_XOR_MULT_DOSStub_d531 {
  strings:
    $key_d531 = { 81 59 [2] f5 41 [2] b2 43 [2] f5 52 [2] bb 5e [2] b7 54 [2] a0 5f [2] bb 11 [2] 86 }

  condition:
    any of them
}