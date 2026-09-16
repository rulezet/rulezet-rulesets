rule TTP_XOR_MULT_DOSStub_85d9 {
  strings:
    $key_85d9 = { d1 b1 [2] a5 a9 [2] e2 ab [2] a5 ba [2] eb b6 [2] e7 bc [2] f0 b7 [2] eb f9 [2] d6 }

  condition:
    any of them
}