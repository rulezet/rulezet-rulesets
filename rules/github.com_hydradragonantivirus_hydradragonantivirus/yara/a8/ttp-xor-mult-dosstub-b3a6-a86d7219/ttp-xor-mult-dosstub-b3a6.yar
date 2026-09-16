rule TTP_XOR_MULT_DOSStub_b3a6 {
  strings:
    $key_b3a6 = { e7 ce [2] 93 d6 [2] d4 d4 [2] 93 c5 [2] dd c9 [2] d1 c3 [2] c6 c8 [2] dd 86 [2] e0 }

  condition:
    any of them
}