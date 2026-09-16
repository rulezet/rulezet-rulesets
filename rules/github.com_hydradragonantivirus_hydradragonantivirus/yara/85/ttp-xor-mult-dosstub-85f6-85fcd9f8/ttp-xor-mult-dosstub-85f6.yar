rule TTP_XOR_MULT_DOSStub_85f6 {
  strings:
    $key_85f6 = { d1 9e [2] a5 86 [2] e2 84 [2] a5 95 [2] eb 99 [2] e7 93 [2] f0 98 [2] eb d6 [2] d6 }

  condition:
    any of them
}