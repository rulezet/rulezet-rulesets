rule TTP_XOR_MULT_DOSStub_85b4 {
  strings:
    $key_85b4 = { d1 dc [2] a5 c4 [2] e2 c6 [2] a5 d7 [2] eb db [2] e7 d1 [2] f0 da [2] eb 94 [2] d6 }

  condition:
    any of them
}