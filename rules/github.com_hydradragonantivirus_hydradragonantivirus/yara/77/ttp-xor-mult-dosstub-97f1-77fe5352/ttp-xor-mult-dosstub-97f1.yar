rule TTP_XOR_MULT_DOSStub_97f1 {
  strings:
    $key_97f1 = { c3 99 [2] b7 81 [2] f0 83 [2] b7 92 [2] f9 9e [2] f5 94 [2] e2 9f [2] f9 d1 [2] c4 }

  condition:
    any of them
}