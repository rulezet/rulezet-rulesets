rule TTP_XOR_MULT_DOSStub_92a4 {
  strings:
    $key_92a4 = { c6 cc [2] b2 d4 [2] f5 d6 [2] b2 c7 [2] fc cb [2] f0 c1 [2] e7 ca [2] fc 84 [2] c1 }

  condition:
    any of them
}