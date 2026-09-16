rule TTP_XOR_MULT_DOSStub_85a4 {
  strings:
    $key_85a4 = { d1 cc [2] a5 d4 [2] e2 d6 [2] a5 c7 [2] eb cb [2] e7 c1 [2] f0 ca [2] eb 84 [2] d6 }

  condition:
    any of them
}