rule TTP_XOR_MULT_DOSStub_97a9 {
  strings:
    $key_97a9 = { c3 c1 [2] b7 d9 [2] f0 db [2] b7 ca [2] f9 c6 [2] f5 cc [2] e2 c7 [2] f9 89 [2] c4 }

  condition:
    any of them
}