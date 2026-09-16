rule TTP_XOR_MULT_DOSStub_96a9 {
  strings:
    $key_96a9 = { c2 c1 [2] b6 d9 [2] f1 db [2] b6 ca [2] f8 c6 [2] f4 cc [2] e3 c7 [2] f8 89 [2] c5 }

  condition:
    any of them
}