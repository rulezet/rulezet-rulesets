rule TTP_XOR_MULT_DOSStub_96e9 {
  strings:
    $key_96e9 = { c2 81 [2] b6 99 [2] f1 9b [2] b6 8a [2] f8 86 [2] f4 8c [2] e3 87 [2] f8 c9 [2] c5 }

  condition:
    any of them
}