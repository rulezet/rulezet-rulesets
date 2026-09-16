rule TTP_XOR_MULT_DOSStub_96e7 {
  strings:
    $key_96e7 = { c2 8f [2] b6 97 [2] f1 95 [2] b6 84 [2] f8 88 [2] f4 82 [2] e3 89 [2] f8 c7 [2] c5 }

  condition:
    any of them
}