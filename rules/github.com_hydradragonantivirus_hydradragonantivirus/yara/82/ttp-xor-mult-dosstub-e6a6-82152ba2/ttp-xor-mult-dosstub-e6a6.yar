rule TTP_XOR_MULT_DOSStub_e6a6 {
  strings:
    $key_e6a6 = { b2 ce [2] c6 d6 [2] 81 d4 [2] c6 c5 [2] 88 c9 [2] 84 c3 [2] 93 c8 [2] 88 86 [2] b5 }

  condition:
    any of them
}