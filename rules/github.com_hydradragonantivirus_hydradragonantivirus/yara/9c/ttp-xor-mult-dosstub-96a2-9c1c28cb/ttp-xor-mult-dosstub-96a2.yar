rule TTP_XOR_MULT_DOSStub_96a2 {
  strings:
    $key_96a2 = { c2 ca [2] b6 d2 [2] f1 d0 [2] b6 c1 [2] f8 cd [2] f4 c7 [2] e3 cc [2] f8 82 [2] c5 }

  condition:
    any of them
}