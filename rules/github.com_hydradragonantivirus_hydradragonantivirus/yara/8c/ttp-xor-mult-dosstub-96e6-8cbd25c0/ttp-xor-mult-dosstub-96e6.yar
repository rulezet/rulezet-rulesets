rule TTP_XOR_MULT_DOSStub_96e6 {
  strings:
    $key_96e6 = { c2 8e [2] b6 96 [2] f1 94 [2] b6 85 [2] f8 89 [2] f4 83 [2] e3 88 [2] f8 c6 [2] c5 }

  condition:
    any of them
}