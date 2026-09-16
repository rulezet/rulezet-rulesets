rule TTP_XOR_MULT_DOSStub_97f0 {
  strings:
    $key_97f0 = { c3 98 [2] b7 80 [2] f0 82 [2] b7 93 [2] f9 9f [2] f5 95 [2] e2 9e [2] f9 d0 [2] c4 }

  condition:
    any of them
}