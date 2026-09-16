rule TTP_XOR_MULT_DOSStub_d5a9 {
  strings:
    $key_d5a9 = { 81 c1 [2] f5 d9 [2] b2 db [2] f5 ca [2] bb c6 [2] b7 cc [2] a0 c7 [2] bb 89 [2] 86 }

  condition:
    any of them
}