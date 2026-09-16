rule TTP_XOR_MULT_DOSStub_41a6 {
  strings:
    $key_41a6 = { 15 ce [2] 61 d6 [2] 26 d4 [2] 61 c5 [2] 2f c9 [2] 23 c3 [2] 34 c8 [2] 2f 86 [2] 12 }

  condition:
    any of them
}