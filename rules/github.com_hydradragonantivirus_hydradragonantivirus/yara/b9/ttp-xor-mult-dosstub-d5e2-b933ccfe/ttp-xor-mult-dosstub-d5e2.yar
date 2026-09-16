rule TTP_XOR_MULT_DOSStub_d5e2 {
  strings:
    $key_d5e2 = { 81 8a [2] f5 92 [2] b2 90 [2] f5 81 [2] bb 8d [2] b7 87 [2] a0 8c [2] bb c2 [2] 86 }

  condition:
    any of them
}