rule TTP_XOR_MULT_DOSStub_95d9 {
  strings:
    $key_95d9 = { c1 b1 [2] b5 a9 [2] f2 ab [2] b5 ba [2] fb b6 [2] f7 bc [2] e0 b7 [2] fb f9 [2] c6 }

  condition:
    any of them
}