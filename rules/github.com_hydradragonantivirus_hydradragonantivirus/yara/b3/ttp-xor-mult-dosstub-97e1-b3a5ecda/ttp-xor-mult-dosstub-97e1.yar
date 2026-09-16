rule TTP_XOR_MULT_DOSStub_97e1 {
  strings:
    $key_97e1 = { c3 89 [2] b7 91 [2] f0 93 [2] b7 82 [2] f9 8e [2] f5 84 [2] e2 8f [2] f9 c1 [2] c4 }

  condition:
    any of them
}