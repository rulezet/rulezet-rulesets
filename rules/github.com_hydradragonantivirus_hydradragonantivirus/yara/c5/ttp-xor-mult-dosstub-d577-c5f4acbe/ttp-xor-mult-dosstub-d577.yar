rule TTP_XOR_MULT_DOSStub_d577 {
  strings:
    $key_d577 = { 81 1f [2] f5 07 [2] b2 05 [2] f5 14 [2] bb 18 [2] b7 12 [2] a0 19 [2] bb 57 [2] 86 }

  condition:
    any of them
}