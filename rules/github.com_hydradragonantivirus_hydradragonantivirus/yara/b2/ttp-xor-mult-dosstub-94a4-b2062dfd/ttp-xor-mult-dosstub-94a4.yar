rule TTP_XOR_MULT_DOSStub_94a4 {
  strings:
    $key_94a4 = { c0 cc [2] b4 d4 [2] f3 d6 [2] b4 c7 [2] fa cb [2] f6 c1 [2] e1 ca [2] fa 84 [2] c7 }

  condition:
    any of them
}