rule TTP_XOR_MULT_DOSStub_45a6 {
  strings:
    $key_45a6 = { 11 ce [2] 65 d6 [2] 22 d4 [2] 65 c5 [2] 2b c9 [2] 27 c3 [2] 30 c8 [2] 2b 86 [2] 16 }

  condition:
    any of them
}