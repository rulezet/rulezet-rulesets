rule TTP_XOR_MULT_DOSStub_85d2 {
  strings:
    $key_85d2 = { d1 ba [2] a5 a2 [2] e2 a0 [2] a5 b1 [2] eb bd [2] e7 b7 [2] f0 bc [2] eb f2 [2] d6 }

  condition:
    any of them
}