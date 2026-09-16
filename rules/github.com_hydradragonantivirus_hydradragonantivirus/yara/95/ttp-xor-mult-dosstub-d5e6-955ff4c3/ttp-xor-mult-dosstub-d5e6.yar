rule TTP_XOR_MULT_DOSStub_d5e6 {
  strings:
    $key_d5e6 = { 81 8e [2] f5 96 [2] b2 94 [2] f5 85 [2] bb 89 [2] b7 83 [2] a0 88 [2] bb c6 [2] 86 }

  condition:
    any of them
}