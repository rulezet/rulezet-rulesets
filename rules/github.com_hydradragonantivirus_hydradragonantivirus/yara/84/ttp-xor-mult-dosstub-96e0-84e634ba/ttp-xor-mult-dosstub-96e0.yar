rule TTP_XOR_MULT_DOSStub_96e0 {
  strings:
    $key_96e0 = { c2 88 [2] b6 90 [2] f1 92 [2] b6 83 [2] f8 8f [2] f4 85 [2] e3 8e [2] f8 c0 [2] c5 }

  condition:
    any of them
}