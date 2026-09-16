rule TTP_XOR_MULT_DOSStub_f1a6 {
  strings:
    $key_f1a6 = { a5 ce [2] d1 d6 [2] 96 d4 [2] d1 c5 [2] 9f c9 [2] 93 c3 [2] 84 c8 [2] 9f 86 [2] a2 }

  condition:
    any of them
}