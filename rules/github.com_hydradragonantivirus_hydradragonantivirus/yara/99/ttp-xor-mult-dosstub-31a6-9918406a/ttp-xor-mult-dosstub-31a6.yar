rule TTP_XOR_MULT_DOSStub_31a6 {
  strings:
    $key_31a6 = { 65 ce [2] 11 d6 [2] 56 d4 [2] 11 c5 [2] 5f c9 [2] 53 c3 [2] 44 c8 [2] 5f 86 [2] 62 }

  condition:
    any of them
}