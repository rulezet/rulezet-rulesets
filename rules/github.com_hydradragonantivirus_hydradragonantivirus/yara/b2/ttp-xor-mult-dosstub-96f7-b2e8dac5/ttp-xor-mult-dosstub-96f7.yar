rule TTP_XOR_MULT_DOSStub_96f7 {
  strings:
    $key_96f7 = { c2 9f [2] b6 87 [2] f1 85 [2] b6 94 [2] f8 98 [2] f4 92 [2] e3 99 [2] f8 d7 [2] c5 }

  condition:
    any of them
}