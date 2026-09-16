rule TTP_XOR_MULT_DOSStub_35a6 {
  strings:
    $key_35a6 = { 61 ce [2] 15 d6 [2] 52 d4 [2] 15 c5 [2] 5b c9 [2] 57 c3 [2] 40 c8 [2] 5b 86 [2] 66 }

  condition:
    any of them
}