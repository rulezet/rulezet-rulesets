rule TTP_XOR_MULT_DOSStub_96f0 {
  strings:
    $key_96f0 = { c2 98 [2] b6 80 [2] f1 82 [2] b6 93 [2] f8 9f [2] f4 95 [2] e3 9e [2] f8 d0 [2] c5 }

  condition:
    any of them
}