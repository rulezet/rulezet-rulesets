rule TTP_XOR_MULT_DOSStub_d5ae {
  strings:
    $key_d5ae = { 81 c6 [2] f5 de [2] b2 dc [2] f5 cd [2] bb c1 [2] b7 cb [2] a0 c0 [2] bb 8e [2] 86 }

  condition:
    any of them
}