rule TTP_XOR_MULT_DOSStub_77a6 {
  strings:
    $key_77a6 = { 23 ce [2] 57 d6 [2] 10 d4 [2] 57 c5 [2] 19 c9 [2] 15 c3 [2] 02 c8 [2] 19 86 [2] 24 }

  condition:
    any of them
}