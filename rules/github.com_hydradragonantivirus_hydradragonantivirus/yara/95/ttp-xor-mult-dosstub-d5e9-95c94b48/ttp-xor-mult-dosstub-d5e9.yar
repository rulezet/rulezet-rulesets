rule TTP_XOR_MULT_DOSStub_d5e9 {
  strings:
    $key_d5e9 = { 81 81 [2] f5 99 [2] b2 9b [2] f5 8a [2] bb 86 [2] b7 8c [2] a0 87 [2] bb c9 [2] 86 }

  condition:
    any of them
}