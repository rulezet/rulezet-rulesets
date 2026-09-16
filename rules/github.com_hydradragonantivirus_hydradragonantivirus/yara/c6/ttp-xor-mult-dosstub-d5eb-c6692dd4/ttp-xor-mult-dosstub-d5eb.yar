rule TTP_XOR_MULT_DOSStub_d5eb {
  strings:
    $key_d5eb = { 81 83 [2] f5 9b [2] b2 99 [2] f5 88 [2] bb 84 [2] b7 8e [2] a0 85 [2] bb cb [2] 86 }

  condition:
    any of them
}