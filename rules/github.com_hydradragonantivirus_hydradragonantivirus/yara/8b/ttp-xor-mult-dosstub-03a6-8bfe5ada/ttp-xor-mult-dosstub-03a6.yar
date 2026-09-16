rule TTP_XOR_MULT_DOSStub_03a6 {
  strings:
    $key_03a6 = { 57 ce [2] 23 d6 [2] 64 d4 [2] 23 c5 [2] 6d c9 [2] 61 c3 [2] 76 c8 [2] 6d 86 [2] 50 }

  condition:
    any of them
}