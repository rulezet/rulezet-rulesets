rule TTP_XOR_MULT_DOSStub_85a6 {
  strings:
    $key_85a6 = { d1 ce [2] a5 d6 [2] e2 d4 [2] a5 c5 [2] eb c9 [2] e7 c3 [2] f0 c8 [2] eb 86 [2] d6 }

  condition:
    any of them
}