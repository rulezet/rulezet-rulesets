rule TTP_XOR_MULT_DOSStub_97d9 {
  strings:
    $key_97d9 = { c3 b1 [2] b7 a9 [2] f0 ab [2] b7 ba [2] f9 b6 [2] f5 bc [2] e2 b7 [2] f9 f9 [2] c4 }

  condition:
    any of them
}