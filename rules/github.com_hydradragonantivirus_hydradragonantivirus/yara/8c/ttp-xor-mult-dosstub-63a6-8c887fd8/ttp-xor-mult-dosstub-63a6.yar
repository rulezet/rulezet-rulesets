rule TTP_XOR_MULT_DOSStub_63a6 {
  strings:
    $key_63a6 = { 37 ce [2] 43 d6 [2] 04 d4 [2] 43 c5 [2] 0d c9 [2] 01 c3 [2] 16 c8 [2] 0d 86 [2] 30 }

  condition:
    any of them
}