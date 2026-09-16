rule TTP_XOR_MULT_DOSStub_97d2 {
  strings:
    $key_97d2 = { c3 ba [2] b7 a2 [2] f0 a0 [2] b7 b1 [2] f9 bd [2] f5 b7 [2] e2 bc [2] f9 f2 [2] c4 }

  condition:
    any of them
}