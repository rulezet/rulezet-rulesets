rule TTP_XOR_MULT_DOSStub_d5e4 {
  strings:
    $key_d5e4 = { 81 8c [2] f5 94 [2] b2 96 [2] f5 87 [2] bb 8b [2] b7 81 [2] a0 8a [2] bb c4 [2] 86 }

  condition:
    any of them
}