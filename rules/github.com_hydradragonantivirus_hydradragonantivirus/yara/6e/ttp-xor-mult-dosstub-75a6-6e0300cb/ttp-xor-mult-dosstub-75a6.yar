rule TTP_XOR_MULT_DOSStub_75a6 {
  strings:
    $key_75a6 = { 21 ce [2] 55 d6 [2] 12 d4 [2] 55 c5 [2] 1b c9 [2] 17 c3 [2] 00 c8 [2] 1b 86 [2] 26 }

  condition:
    any of them
}