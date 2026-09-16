rule TTP_XOR_MULT_DOSStub_d530 {
  strings:
    $key_d530 = { 81 58 [2] f5 40 [2] b2 42 [2] f5 53 [2] bb 5f [2] b7 55 [2] a0 5e [2] bb 10 [2] 86 }

  condition:
    any of them
}