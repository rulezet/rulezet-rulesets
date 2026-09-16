rule TTP_XOR_MULT_DOSStub_96f5 {
  strings:
    $key_96f5 = { c2 9d [2] b6 85 [2] f1 87 [2] b6 96 [2] f8 9a [2] f4 90 [2] e3 9b [2] f8 d5 [2] c5 }

  condition:
    any of them
}