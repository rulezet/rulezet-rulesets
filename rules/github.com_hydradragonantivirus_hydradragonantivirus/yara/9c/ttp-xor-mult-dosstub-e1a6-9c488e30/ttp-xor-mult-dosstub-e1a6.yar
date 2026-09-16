rule TTP_XOR_MULT_DOSStub_e1a6 {
  strings:
    $key_e1a6 = { b5 ce [2] c1 d6 [2] 86 d4 [2] c1 c5 [2] 8f c9 [2] 83 c3 [2] 94 c8 [2] 8f 86 [2] b2 }

  condition:
    any of them
}