rule TTP_XOR_MULT_DOSStub_95d2 {
  strings:
    $key_95d2 = { c1 ba [2] b5 a2 [2] f2 a0 [2] b5 b1 [2] fb bd [2] f7 b7 [2] e0 bc [2] fb f2 [2] c6 }

  condition:
    any of them
}