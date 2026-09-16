rule TTP_XOR_MULT_DOSStub_d5fb {
  strings:
    $key_d5fb = { 81 93 [2] f5 8b [2] b2 89 [2] f5 98 [2] bb 94 [2] b7 9e [2] a0 95 [2] bb db [2] 86 }

  condition:
    any of them
}