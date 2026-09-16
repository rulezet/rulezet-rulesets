rule TTP_XOR_MULT_DOSStub_d537 {
  strings:
    $key_d537 = { 81 5f [2] f5 47 [2] b2 45 [2] f5 54 [2] bb 58 [2] b7 52 [2] a0 59 [2] bb 17 [2] 86 }

  condition:
    any of them
}