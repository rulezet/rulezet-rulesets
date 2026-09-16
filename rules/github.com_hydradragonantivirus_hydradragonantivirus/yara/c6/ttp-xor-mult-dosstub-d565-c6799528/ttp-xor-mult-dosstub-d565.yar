rule TTP_XOR_MULT_DOSStub_d565 {
  strings:
    $key_d565 = { 81 0d [2] f5 15 [2] b2 17 [2] f5 06 [2] bb 0a [2] b7 00 [2] a0 0b [2] bb 45 [2] 86 }

  condition:
    any of them
}