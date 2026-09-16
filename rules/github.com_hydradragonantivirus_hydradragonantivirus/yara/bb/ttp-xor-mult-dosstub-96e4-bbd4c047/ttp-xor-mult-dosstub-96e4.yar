rule TTP_XOR_MULT_DOSStub_96e4 {
  strings:
    $key_96e4 = { c2 8c [2] b6 94 [2] f1 96 [2] b6 87 [2] f8 8b [2] f4 81 [2] e3 8a [2] f8 c4 [2] c5 }

  condition:
    any of them
}